namespace LoginAPI.Services.Interfaces;

public interface IMyEmailSender
{
    Task SendEmailAsync(string email, string subject, string htmlMessage);
}
