/**
 * Mail Scorer - Gmail add-on.
 *
 *
 * Config lives in Script Properties (Project Settings > Script properties):
 *   BACKEND_URL  e.g. https://mail-scorer-xxxx.a.run.app
 *   API_KEY      shared secret, same value as the backend's API_KEY
 */

// Limits mirror the backend's validation (slightly lower, to stay inside them).
var LIMITS = {
  headers: 60000,
  subject: 1900,
  text: 95000,
  html: 290000,
  attachments: 25,
  hashBytes: 10 * 1024 * 1024 // hash files up to 10 MB
};

var SEVERITY_STYLE = {
  critical: { icon: '🔴', label: 'Critical' },
  high: { icon: '🔴', label: 'High risk' },
  medium: { icon: '🟠', label: 'Medium risk' },
  low: { icon: '🟡', label: 'Low risk' },
  trust: { icon: '🟢', label: 'Reassuring' }
};

var LEVEL_COLOR = {
  safe: '#188038',
  suspicious: '#E37400',
  likely_malicious: '#D93025',
  malicious: '#A50E0E'
};

var MAX_FINDINGS_SHOWN = 8;
var VISIBLE_FINDINGS = 3;
var LRM = '‎'; // keeps "37 / 100" in order inside right-to-left Gmail

// ---------------------------------------------------------------- triggers

function onHomepage(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText('Open an email to scan it.')))
    .build();
}

function onGmailMessageOpen(e) {
  try {
    // Grants access to the open message only (current.message scope).
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var message = GmailApp.getMessageById(e.gmail.messageId);
    var result = callBackend_('/analyze', extractEmail_(message));
    return buildResultCard_(result);
  } catch (err) {
    // Never show raw errors to the user (they may contain URLs or internals).
    console.error('Analysis failed: ' + err.message);
    return buildErrorCard_();
  }
}

// -------------------------------------------------------------- extraction

function extractEmail_(message) {
  return {
    raw_headers: truncate_(rawHeaders_(message), LIMITS.headers),
    subject: truncate_(message.getSubject(), LIMITS.subject),
    body_text: truncate_(message.getPlainBody(), LIMITS.text),
    body_html: truncate_(message.getBody(), LIMITS.html),
    attachments: extractAttachments_(message)
  };
}

/** The header block is everything before the first empty line of the raw message. */
function rawHeaders_(message) {
  var raw = message.getRawContent();
  var end = raw.search(/\r?\n\r?\n/);
  return end >= 0 ? raw.substring(0, end) : raw;
}

/** Metadata and SHA-256 only: file contents never leave the mailbox. */
function extractAttachments_(message) {
  var attachments = message.getAttachments({ includeInlineImages: false });
  return attachments.slice(0, LIMITS.attachments).map(function (blob) {
    var size = blob.getSize();
    return {
      name: truncate_(blob.getName(), 300),
      content_type: truncate_(blob.getContentType(), 200),
      size: size,
      sha256: size <= LIMITS.hashBytes ? sha256Hex_(blob.getBytes()) : ''
    };
  });
}

function sha256Hex_(bytes) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest.map(function (b) {
    var hex = (b < 0 ? b + 256 : b).toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  }).join('');
}

// ----------------------------------------------------------------- backend

function callBackend_(path, payload) {
  var props = PropertiesService.getScriptProperties();
  var baseUrl = props.getProperty('BACKEND_URL');
  var apiKey = props.getProperty('API_KEY');
  if (!baseUrl || !apiKey) {
    throw new Error('Add-on is not configured');
  }

  var response = UrlFetchApp.fetch(baseUrl + path, {
    method: 'post',
    contentType: 'application/json',
    headers: { 'X-Api-Key': apiKey },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  var code = response.getResponseCode();
  if (code !== 200) {
    throw new Error('Backend returned HTTP ' + code);
  }
  return JSON.parse(response.getContentText());
}

// -------------------------------------------------------------------- cards

function buildResultCard_(result) {
  var baseUrl = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');
  var color = LEVEL_COLOR[result.level] || '#5F6368';
  var score = Number(result.score);

  var verdictSection = CardService.newCardSection();
  if (isPath_(result.gauge_path, '/gauge/')) {
    // Animated gauge: the image URL contains only the score, never email data.
    verdictSection.addWidget(CardService.newImage()
      .setImageUrl(baseUrl + result.gauge_path)
      .setAltText('Risk score ' + score + ' out of 100: ' + result.verdict));
  } else {
    verdictSection.addWidget(CardService.newDecoratedText()
      .setTopLabel('Risk score')
      .setText('<font color="' + color + '"><b>' + LRM + score + ' / 100</b></font>'));
  }
  verdictSection.addWidget(CardService.newTextParagraph()
    .setText(ltr_('<font color="' + color + '"><b>' + escapeHtml_(result.verdict) + '.</b></font> ' +
      escapeHtml_(result.summary))));

  // Name the external checks that actually ran; turned-off ones are not shown.
  var ran = (result.checks || []).filter(function (c) { return c.status === 'ok'; })
    .map(function (c) { return escapeHtml_(c.name); });
  if (ran.length) {
    verdictSection.addWidget(CardService.newTextParagraph().setText(
      ltr_('<font color="#5F6368">Also checked with: ' + ran.join(', ') + '</font>')));
  }

  if (isPath_(result.report_path, '/report/')) {
    verdictSection.addWidget(CardService.newButtonSet().addButton(
      CardService.newTextButton()
        .setText('Open full report')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOpenLink(CardService.newOpenLink()
          .setUrl(baseUrl + result.report_path)
          .setOpenAs(CardService.OpenAs.FULL_SIZE))));
  }

  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(verdictSection);

  var shown = (result.findings || []).filter(function (f) {
    return SEVERITY_STYLE[f.severity];
  }).slice(0, MAX_FINDINGS_SHOWN);

  if (shown.length) {
    var reasons = CardService.newCardSection().setHeader('Why');
    shown.forEach(function (finding) {
      reasons.addWidget(CardService.newTextParagraph().setText(ltr_(formatFinding_(finding))));
    });
    if (shown.length > VISIBLE_FINDINGS) {
      // Top reasons stay visible; the rest fold behind "Show more".
      reasons.setCollapsible(true).setNumUncollapsibleWidgets(VISIBLE_FINDINGS);
    }
    card.addSection(reasons);
  }
  return card.build();
}

/** Only follow backend paths of the expected shape. */
function isPath_(path, prefix) {
  return typeof path === 'string' && path.indexOf(prefix) === 0 && /^[\w\/.\-]+$/.test(path);
}

function formatFinding_(finding) {
  var style = SEVERITY_STYLE[finding.severity];
  var html = style.icon + ' <b>' + escapeHtml_(finding.title) + '</b><br>' +
    escapeHtml_(finding.explanation);
  if (finding.evidence && finding.evidence.length) {
    html += '<br><font color="#5F6368">' +
      finding.evidence.map(escapeHtml_).join('<br>') + '</font>';
  }
  return html;
}

/**
 * Wrap English text in left-to-right marks. In right-to-left Gmail (e.g. Hebrew)
 * this keeps periods and quotes at the edges of a sentence on the correct side.
 */
function ltr_(html) {
  return LRM + html + LRM;
}

function buildErrorCard_() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        'Could not analyze this email right now. Please try again.')))
    .build();
}

// ------------------------------------------------------------------ helpers

function truncate_(value, max) {
  value = value || '';
  return value.length > max ? value.substring(0, max) : value;
}

// Card text supports basic HTML, so anything derived from the email
// must be escaped before display.
function escapeHtml_(text) {
  return String(text == null ? '' : text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
