namespace AutoScope.Models
{
    public interface IAiAuditable
    {
        /// <summary>
        /// Returns a structured, plain-text representation of the current tab's state 
        /// (e.g. visible rows, active rules) to be sent to the AI for analysis.
        /// </summary>
        string GetAuditContext();
    }
}
