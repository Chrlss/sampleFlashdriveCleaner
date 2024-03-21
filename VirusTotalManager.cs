using VirusTotalNet;
using VirusTotalNet.Objects;
using VirusTotalNet.Results;

public class VirusTotalManager
{
    private readonly VirusTotal _virusTotal;

    public VirusTotalManager(string apiKey)
    {
        _virusTotal = new VirusTotal(apiKey);
    }

    public async Task<ScanResult> ScanFileAsync(string filePath)
    {
        return await _virusTotal.ScanFileAsync(filePath);
    }
}
