using System.Diagnostics.Eventing.Reader;

namespace RDP_AbuseIPDB
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var yesterday = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day - 1).ToUniversalTime().ToString("o");
            var queryStr = $"*[System[EventID=4625]] and *[System[TimeCreated[@SystemTime>='{yesterday}']]]";

            using var loginEventPropertySelector = new EventLogPropertySelector(new[] {
                "Event/EventData/Data[@Name='TargetUserName']",
                "Event/EventData/Data[@Name='IpAddress']",
            });
            using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, queryStr));

            Console.WriteLine("IP,Categories,ReportDate,Comment");

            var knownIp = new List<string>();
            while (reader.ReadEvent() is { } ev)
            {
                using (ev)
                {
                    var eventTime = ev.TimeCreated?.ToUniversalTime().ToString("s") ?? "";
                    var loginPropertyValues = ((EventLogRecord)ev).GetPropertyValues(loginEventPropertySelector);

                    // var user = loginPropertyValues[0].ToString() ?? "";
                    var ipAddress = loginPropertyValues[1].ToString() ?? "";

                    if (ipAddress.Length == 0 || knownIp.Contains(ipAddress)) continue;

                    knownIp.Add(ipAddress);

                    Console.WriteLine($"{ipAddress},18,{eventTime},\"RDP Attack\"");
                }
            }
        }
    }
}