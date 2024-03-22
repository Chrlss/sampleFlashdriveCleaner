using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using VirusTotalNet;



namespace sample
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static class MessageBoxButtonCustom
        {
            public static MessageBoxButton YesNoCancel(string yesContent, string noContent, string cancelContent)
            {
                return new MessageBoxButton
                {
                    Yes = new MessageBoxCustomButton(yesContent, MessageBoxResult.Yes),
                    No = new MessageBoxCustomButton(noContent, MessageBoxResult.No),
                    Cancel = new MessageBoxCustomButton(cancelContent, MessageBoxResult.Cancel)
                };
            }
        }

        public class MessageBoxButton
        {
            public MessageBoxCustomButton Yes { get; set; }
            public MessageBoxCustomButton No { get; set; }
            public MessageBoxCustomButton Cancel { get; set; }
        }

        public class MessageBoxCustomButton
        {
            public string Content { get; set; }
            public MessageBoxResult Result { get; set; }

            public MessageBoxCustomButton(string content, MessageBoxResult result)
            {
                Content = content;
                Result = result;
            }
        }


        private class RemovableDriveInfo
        {
            public string DriveLetter { get; set; }
            public bool IsRemoved { get; set; }
        }

        private List<string> _suspiciousFiles;
        private string _driveLetter;
        private StreamWriter _logWriter;
        private string _logFilePath = Path.Combine(Path.GetTempPath(), "scan_log.txt");
        private List<RemovableDriveInfo> _removableDrives = new List<RemovableDriveInfo>();

        private const string VirusTotalApiKey = "00fc286349bdbca1e47b6e78a07cc4791195a230d4f64a44421c6726a5126354";

        public MainWindow()
        {
            InitializeComponent();

            ScanWithVirusTotalButton.Click += ScanWithVirusTotal_Click;

            // Disable the "Scan and Clean Flash Drive" button by default
            ScanAndCleanFlashDriveButton.IsEnabled = false;

            // Initialize log file
            _logWriter = new StreamWriter(_logFilePath, append: true);
            Log("Application started");

            // Start a thread to periodically check for removable drives
            var driveDetectionThread = new Thread(() =>
            {
                while (true)
                {
                    // Get the list of drives on the system
                    var drives = DriveInfo.GetDrives();

                    // Check if any of the drives are removable drives
                    var removableDrives = drives.Where(d => d.DriveType == DriveType.Removable).ToList();
                    // Check for newly detected removable drives
                    foreach (var drive in removableDrives)
                    {
                        if (!_removableDrives.Any(d => d.DriveLetter == drive.Name))
                        {
                            // Log the detection of a removable drive
                            Log($"USB flashdrive detected");

                            // Add the drive to the list of removable drives
                            _removableDrives.Add(new RemovableDriveInfo { DriveLetter = drive.Name, IsRemoved = false });

                            // Automatically start the scan
                            Dispatcher.Invoke(() => ScanAndCleanFlashDrive_Click(this, new RoutedEventArgs()));
                        }
                    }

                    // Check for removed removable drives
                    foreach (var drive in _removableDrives.ToList())
                    {
                        if (!removableDrives.Any(d => d.Name == drive.DriveLetter))
                        {
                            // Log the removal of a removable drive
                            Log($"USB flashdrive removed");

                            // Remove the drive from the list of removable drives
                            _removableDrives.Remove(drive);
                        }
                    }

                    // Wait for 5 seconds before checking again
                    Thread.Sleep(5000);
                }
            });

            driveDetectionThread.IsBackground = true;
            driveDetectionThread.Start();
        }
        
        private async void ScanWithVirusTotal_Click(object sender, RoutedEventArgs e)
        {
            foreach (var file in _suspiciousFiles)
            {
                try
                {
                    // Initialize the VirusTotal API client
                    var client = new VirusTotalNet.VirusTotal(VirusTotalApiKey);

                    // Get the file hash
                    var fileStream = await HashFile(file);

                    // Scan the file with VirusTotal
                    var scanResult = await client.ScanFileAsync(fileStream, Path.GetFileName(file));
                    var isMalware = scanResult.ResponseCode > 0;

                    // Log the result
                    if (isMalware)
                    {
                        Log($"File {file} is malware according to VirusTotal");
                        var result = MessageBox.Show($"The file '{file}' is flagged as malware. Do you want to clean it?", "Malware Detected", System.Windows.MessageBoxButton.YesNo);
                        if (result == MessageBoxResult.Yes)
                        {
                            // Clean the file (implementation depends on your chosen method)
                            // You can call a separate function to handle cleaning logic
                            CleanFile(file);
                            Log($"File {file} cleaned");
                        }
                    }
                    else
                    {
                        Log($"File {file} is not detected as malware by VirusTotal");
                    }

                    // Close the file stream
                    fileStream.Close();
                }
                catch (Exception ex)
                {
                    // Log the exception
                    Log($"Error scanning file {file}: {ex.Message}");
                }
            }
        }

        private void CleanFile(string filePath)
        {
            try
            {
                // Attempt to delete the file
                File.Delete(filePath);
                Log($"File {filePath} deleted");
            }
            catch (Exception ex)
            {
                // Log the error message if deletion fails
                Log($"Error deleting file {filePath}: {ex.Message}");
            }
        }

        private async Task<Stream> HashFile(string file)
        {
            using (var stream = File.OpenRead(file))
            {
                using (var md5 = MD5.Create())
                {
                    // Calculate the MD5 hash of the file
                    byte[] hashBytes = await md5.ComputeHashAsync(stream);

                    // Reset the position of the stream to the beginning
                    stream.Seek(0, SeekOrigin.Begin);

                    // Return a MemoryStream containing the hash bytes
                    return new MemoryStream(hashBytes);
                }
            }
        }


        public List<string> ScanFlashDrive(string driveLetter)
        {
            var suspiciousFiles = new List<string>();

            // Get the root directory of the flash drive
            var rootDirectory = new DirectoryInfo(driveLetter + ":\\");

            // Recursively scan all directories and subdirectories
            ScanDirectory(rootDirectory, suspiciousFiles);

            return suspiciousFiles;
        }

        private void Log(string message)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string logMessage = $"[{timestamp}] {message}\n";

            // Update the LogTextBox on the UI thread
            Dispatcher.Invoke(() =>
            {
                // Append the new log message to the TextBox
                LogTextBox.AppendText(logMessage);
                LogTextBox.ScrollToEnd(); // Scroll to the end to show the latest log message
            });
        }

        private void ScanDirectory(DirectoryInfo directory, List<string> suspiciousFiles)
        {
            // Scan all files in the current directory
            foreach (var file in directory.GetFiles())
            {
                // Check if the file extension is suspicious
                if (IsSuspiciousFileExtension(file.Extension))
                {
                    suspiciousFiles.Add(file.FullName);
                }
            }

            // Recursively scan all subdirectories
            foreach (var subdirectory in directory.GetDirectories())
            {
                ScanDirectory(subdirectory, suspiciousFiles);
            }
        }
        private bool IsSuspiciousFileExtension(string extension)
        {
            // Define a list of suspicious file extensions
            var suspiciousExtensions = new List<string> { ".exe", ".bat", ".vbs", ".js", ".lnk", ".bmp", ".etl"};

            // Check if the file extension is in the list of suspicious extensions
            return suspiciousExtensions.Contains(extension.ToLower());
        }

        public void CleanFlashDrive(string driveLetter)
        {
            // Get the root directory of the flash drive
            var rootDirectory = new DirectoryInfo(driveLetter + ":\\");

            // Recursively scan all directories and subdirectories
            CleanDirectory(rootDirectory);

            
        }
        private void CleanDirectory(DirectoryInfo directory)
        {
            // Delete all suspicious files in the current directory
            foreach (var file in directory.GetFiles())
            {
                if (IsSuspiciousFile(file))
                {
                    try
                    {
                        file.Delete();
                    }
                    catch (Exception ex)
                    {
                        // Log the exception
                        // ...

                        // Display a message to the user
                        MessageBox.Show($"Error deleting file {file.Name}:{ex.Message}", "Error", System.Windows.MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }

            // Recursively delete all suspicious files in the subdirectories
            foreach (var subdirectory in directory.GetDirectories())
            {
                CleanDirectory(subdirectory);
            }

            // Delete the directory if it is empty
            if (directory.GetFiles().Length == 0 && directory.GetDirectories().Length == 0)
            {
                try
                {
                    directory.Delete();
                }
                catch (Exception ex)
                {
                    // Log the exception
                    // ...

                    // Display a message to the user
                    MessageBox.Show($"Error deleting directory {directory.Name}: {ex.Message}", "Error", System.Windows.MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private bool IsSuspiciousFile(FileInfo file)
        {
            // Check if the file extension is suspicious
            if (IsSuspiciousFileExtension(file.Extension))
            {
                return true;
            }

            // Check if the file name is suspicious
            if (IsSuspiciousFileName(file.Name))
            {
                return true;
            }

            return false;
        }

        private bool IsSuspiciousFileName(string fileName)
        {
            // Define a list of suspicious file names
            var suspiciousFileNames = new List<string> { "autorun.inf", "thumbs.db", "boot.ini", "ntldr" };

            // Check if the file name is in the list of suspicious file names
            return suspiciousFileNames.Contains(fileName.ToLower());
        }

        private async void ScanAndCleanFlashDrive_Click(object sender, RoutedEventArgs e)
        {
            string driveLetter = "F"; // Set this to the letter of the flash drive
            Log($"Scanning flash drive {driveLetter} started");
            _suspiciousFiles = ScanFlashDrive(driveLetter);
            if (_suspiciousFiles.Count > 0)
            {
                Log($"Suspicious files found: {_suspiciousFiles.Count}");
                Log($"The following suspicious files were found:\n\n{string.Join("\n", _suspiciousFiles)}");
                await ScanWithVirusTotalAsync(); // Call the ScanWithVirusTotal_Click method asynchronously
            }
            else
            {
                Log("No suspicious files found on the flash drive.");
                Log("No suspicious files were found on the flash drive.");
            }
        }

        private async Task ScanWithVirusTotalAsync()
        {
            List<string> detectedMalware = new List<string>();

            foreach (var file in _suspiciousFiles)
            {
                try
                {
                    // Initialize the VirusTotal API client
                    var client = new VirusTotalNet.VirusTotal(VirusTotalApiKey);

                    // Get the file hash
                    var fileStream = await HashFile(file);

                    // Scan the file with VirusTotal
                    var scanResult = await client.ScanFileAsync(fileStream, Path.GetFileName(file));
                    var isMalware = scanResult.ResponseCode > 0;

                    // Log the result
                    if (isMalware)
                    {
                        detectedMalware.Add(file); // Add the detected malware file to the list

                        // No need to prompt here, we'll do it after scanning all files
                    }
                    else
                    {
                        Log($"File {file} is not detected as malware by VirusTotal");
                    }

                    // Close the file stream
                    fileStream.Close();
                }
                catch (Exception ex)
                {
                    // Log the exception
                    Log($"Error scanning file {file}: {ex.Message}");
                }
            }

            // Display the list of detected malware files with an option to clean them all or reformat the flash drive
            if (detectedMalware.Any())
            {
                string message = $"The following files are flagged as malware:\n\n{string.Join("\n", detectedMalware)}\n\nDo you want to clean them all or reformat the flash drive?";
                var result = MessageBox.Show(message, "Malware Detected", System.Windows.MessageBoxButton.YesNoCancel);
                if (result == MessageBoxResult.Yes)
                {
                    foreach (var file in detectedMalware)
                    {
                        CleanFile(file);
                        Log($"File {file} cleaned");
                    }
                }
                else if (result == MessageBoxResult.Cancel)
                {
                    // Reformat the flash drive
                    ReformatFlashDrive();
                    Log($"Flash drive reformatted");
                }
            }
            else
            {
                MessageBox.Show("No malware detected.", "Malware Detected", System.Windows.MessageBoxButton.OK);
            }
        }

        private void ReformatFlashDrive()
        {
            try
            {
                string driveLetter = "F"; // Replace with the appropriate drive letter
                string command = $"format {driveLetter}: /FS:FAT32 /Q /X"; // Command to format the drive as FAT32

                // Start a new process to execute the command
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe")
                {
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                Process process = Process.Start(psi);
                process.StandardInput.WriteLine(command);
                process.StandardInput.Flush();
                process.StandardInput.Close();
                process.WaitForExit();

                // Check the exit code to determine if the format was successful
                if (process.ExitCode == 0)
                {
                    Log($"Flash drive formatted successfully");
                }
                else
                {
                    Log($"Error formatting flash drive");
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                Log($"Error formatting flash drive: {ex.Message}");
                // Display a message to the user
                MessageBox.Show($"Error formatting flash drive: {ex.Message}", "Error", System.Windows.MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }



        protected override void OnClosing(CancelEventArgs e)
        {
            base.OnClosing(e);

            // Close the log file
            _logWriter.Close();
        }

    }
}
       