const nodeMailer = require("nodemailer");

class MailService {
  constructor() {
    this.transporter = nodeMailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
  }
  async sendActivationMail(to, link) {
    await this.transporter.sendMail({
      from: process.env.SMTP_USER,
      to,
      subject: "Activation list" + process.env.API_URL,
      text: "",
      html: `<div>
          <h1>For activation user go to link</h1>
          <a href="${link}">${link}</a>
        </div>`,
    });
  }
}

module.exports = new MailService();
