const nodemailer = require("nodemailer");

function getTransport() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const secure = String(process.env.SMTP_SECURE || "false") === "true";

  if (!host || !port || !user || !pass) {
    const err = new Error("SMTP is not configured");
    err.statusCode = 500;
    err.code = "SMTP_NOT_CONFIGURED";
    throw err;
  }

  return nodemailer.createTransport({ host, port, secure, auth: { user, pass } });
}

async function sendContactEmail({ name, email, phone, subject, message }) {
  const to = process.env.TO_EMAIL;
  if (!to) {
    const err = new Error("TO_EMAIL missing");
    err.statusCode = 500;
    err.code = "TO_EMAIL_MISSING";
    throw err;
  }

  const from = process.env.FROM_EMAIL || `Portfolio Contact <${process.env.SMTP_USER}>`;
  const safeSubject = subject ? subject : "New contact form message";

  const text =
`New message from portfolio contact form

Name: ${name}
Email: ${email}
Phone: ${phone || "-"}
Subject: ${safeSubject}

Message:
${message}
`;

  const transport = getTransport();
  await transport.sendMail({ from, to, replyTo: email, subject: `[Portfolio] ${safeSubject}`, text });
}

module.exports = { sendContactEmail };
