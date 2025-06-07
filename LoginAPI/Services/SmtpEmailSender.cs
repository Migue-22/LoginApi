using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using LoginAPI.Services.Interfaces;
using LoginAPI.Services.Configs;

namespace LoginAPI.Services;



public class SmtpEmailSender : IMyEmailSender
{
    private readonly SmtpSettings _settings;

    public SmtpEmailSender(SmtpSettings settings)
    {
        _settings = settings;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        using var client = new SmtpClient(_settings.Host, _settings.Port)
        {
            Credentials = new NetworkCredential(_settings.Username, _settings.Password),
            EnableSsl = _settings.EnableSsl,
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_settings.SenderEmail, _settings.SenderName),
            Subject = subject,
            Body = htmlMessage,
            IsBodyHtml = true,
        };

        mailMessage.To.Add(email);

        await client.SendMailAsync(mailMessage);
    }
}
