/**
 * Mail Scorer - Gmail add-on (phase 1).
 *
 * The add-on stays thin: extract the open message, send a minimal payload
 * to the backend, render the result. No analysis logic and no third-party
 * API keys live here.
 *
 * Config lives in Script Properties (Project Settings > Script properties):
 *   BACKEND_URL  e.g. https://mail-scorer-xxxx.a.run.app
 *   API_KEY      shared secret, same value as the backend's API_KEY
 */

var MAX_SUBJECT = 1000;
var MAX_SENDER = 500;

function onHomepage(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText('Open an email to scan it.')))
    .build();
}

function onGmailMessageOpen(e) {
  // Grants access to the open message only (current.message scope).
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);

  var payload = {
    subject: truncate_(message.getSubject(), MAX_SUBJECT),
    sender: truncate_(message.getFrom(), MAX_SENDER)
  };

  try {
    return buildResultCard_(callBackend_('/analyze', payload));
  } catch (err) {
    // Never show raw errors (they may contain URLs or internals).
    console.error('Analysis failed: ' + err.message);
    return buildErrorCard_();
  }
}

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

function buildResultCard_(result) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Score')
      .setText(String(result.score) + ' / 100'))
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText(escapeHtml_(result.verdict)));

  (result.reasons || []).forEach(function (reason) {
    section.addWidget(CardService.newTextParagraph().setText('• ' + escapeHtml_(reason)));
  });

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(section)
    .build();
}

function buildErrorCard_() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Mail Scorer'))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        'Could not analyze this email right now. Please try again.')))
    .build();
}

function truncate_(value, max) {
  value = value || '';
  return value.length > max ? value.substring(0, max) : value;
}

// Card text supports basic HTML, so anything derived from the email
// must be escaped before display.
function escapeHtml_(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
