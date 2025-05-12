using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using System.Collections.Generic;
using System.Text;
using EncryptionCore;
using System.Security.Cryptography;

namespace EncryptionUI
{
    public partial class MainWindow : Window
    {
        // Path to the Python script
        private readonly string PythonScriptPath;

        public MainWindow()
        {
            InitializeComponent();
            
            // Set the path to the Python script
            PythonScriptPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), 
                "TN", "v0.40.py");

            // Setup event handlers
            SetupEventHandlers();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        private void SetupEventHandlers()
        {
            // Folder browser buttons
            this.FindControl<Button>("BrowseSourceButton").Click += async (s, e) => 
                this.FindControl<TextBox>("SourceFolderTextBox").Text = await SelectFolder("Select folder to encrypt");
                
            this.FindControl<Button>("BrowseDestButton").Click += async (s, e) => 
                this.FindControl<TextBox>("DestFolderTextBox").Text = await SelectFolder("Select destination folder");
                
            this.FindControl<Button>("BrowseKeyDirButton").Click += async (s, e) => 
                this.FindControl<TextBox>("KeyDirTextBox").Text = await SelectFolder("Select key directory");
                
            this.FindControl<Button>("BrowseEncryptedButton").Click += async (s, e) => 
                this.FindControl<TextBox>("EncryptedFolderTextBox").Text = await SelectFolder("Select encrypted folder");
                
            this.FindControl<Button>("BrowseDecryptedButton").Click += async (s, e) => 
                this.FindControl<TextBox>("DecryptedFolderTextBox").Text = await SelectFolder("Select decryption destination");
                
            this.FindControl<Button>("BrowseDecryptKeyDirButton").Click += async (s, e) => 
                this.FindControl<TextBox>("DecryptKeyDirTextBox").Text = await SelectFolder("Select key directory");
                
            this.FindControl<Button>("BrowseKeyOutputDirButton").Click += async (s, e) => 
                this.FindControl<TextBox>("KeyOutputDirTextBox").Text = await SelectFolder("Select key output directory");
                
            this.FindControl<Button>("BrowseAWSKeyDirButton").Click += async (s, e) => 
                this.FindControl<TextBox>("AWSKeyDirTextBox").Text = await SelectFolder("Select key directory");
                
            this.FindControl<Button>("BrowseKeySharesDirButton").Click += async (s, e) => 
                this.FindControl<TextBox>("KeySharesDirTextBox").Text = await SelectFolder("Select key shares directory");
                
            this.FindControl<Button>("BrowseRetrieveOutputDirButton").Click += async (s, e) => 
                this.FindControl<TextBox>("RetrieveOutputDirTextBox").Text = await SelectFolder("Select output directory");
                
            this.FindControl<Button>("BrowseDeleteKeysDirButton").Click += async (s, e) => 
                this.FindControl<TextBox>("DeleteKeysDirTextBox").Text = await SelectFolder("Select directory with keys to delete");

            // Action buttons
            this.FindControl<Button>("EncryptButton").Click += EncryptButton_Click;
            this.FindControl<Button>("DecryptButton").Click += DecryptButton_Click;
            this.FindControl<Button>("GenerateRSAButton").Click += GenerateRSAButton_Click;
            this.FindControl<Button>("StoreKeyButton").Click += StoreKeyButton_Click;
            this.FindControl<Button>("StoreSharesButton").Click += StoreSharesButton_Click;
            this.FindControl<Button>("RetrieveKeyButton").Click += RetrieveKeyButton_Click;
            this.FindControl<Button>("RetrieveSharesButton").Click += RetrieveSharesButton_Click;
            this.FindControl<Button>("DeleteLocalKeysButton").Click += DeleteLocalKeysButton_Click;
        }

        private async Task<string> SelectFolder(string title)
        {
            var dialog = new OpenFolderDialog
            {
                Title = title
            };

            var result = await dialog.ShowAsync(this);
            return result;
        }

        private async void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            var SourceFolderTextBox = this.FindControl<TextBox>("SourceFolderTextBox");
            var DestFolderTextBox = this.FindControl<TextBox>("DestFolderTextBox");
            var EncryptionStatus = this.FindControl<TextBlock>("EncryptionStatus");
            var EncryptionProgress = this.FindControl<ProgressBar>("EncryptionProgress");
            var EncryptButton = this.FindControl<Button>("EncryptButton");

            if (string.IsNullOrWhiteSpace(SourceFolderTextBox.Text) || 
                string.IsNullOrWhiteSpace(DestFolderTextBox.Text))
            {
                EncryptionStatus.Text = "Please fill in all required fields.";
                return;
            }

            EncryptButton.IsEnabled = false;
            EncryptionProgress.IsVisible = true;
            EncryptionProgress.IsIndeterminate = true;
            EncryptionStatus.Text = "Encrypting...";

            var stopwatch = new Stopwatch();
            long totalBytes = 0;
            try
            {
                string inputFolder = SourceFolderTextBox.Text;
                string outputFolder = DestFolderTextBox.Text;
                if (!Directory.Exists(outputFolder))
                    Directory.CreateDirectory(outputFolder);

                var files = Directory.GetFiles(inputFolder);
                int total = files.Length;
                int count = 0;
                stopwatch.Start();
                foreach (var file in files)
                {
                    string fileName = Path.GetFileName(file);
                    string outFile = Path.Combine(outputFolder, fileName + ".enc");
                    byte[] key = new byte[32];
                    RandomNumberGenerator.Fill(key);
                    byte[] iv = new byte[12];
                    RandomNumberGenerator.Fill(iv);
                    long fileSize = new FileInfo(file).Length;
                    await Task.Run(() => EncryptionService.EncryptFile(file, outFile, key, iv));
                    totalBytes += fileSize;
                    // Save key to KeyStorage
                    string keyDir = Path.Combine(Directory.GetCurrentDirectory(), "KeyStorage");
                    if (!Directory.Exists(keyDir)) Directory.CreateDirectory(keyDir);
                    string keyFilePath = Path.Combine(keyDir, fileName + ".key");
                    File.WriteAllBytes(keyFilePath, key);
                    count++;
                    EncryptionStatus.Text = $"Encrypted {count}/{total} files. Key saved: {keyFilePath}";
                }
                stopwatch.Stop();
                double seconds = stopwatch.Elapsed.TotalSeconds;
                double gb = totalBytes / 1_073_741_824.0;
                double speed = seconds > 0 ? gb / seconds : 0;
                double estTime1GB = speed > 0 ? 1.0 / speed : 0; // seconds to process 1GB
                string sizeStr = totalBytes >= 1_073_741_824 ? $"{gb:F2} GB" :
                                 totalBytes >= 1_048_576 ? $"{totalBytes / 1_048_576.0:F2} MB" :
                                 $"{totalBytes / 1024.0:F2} KB";
                EncryptionStatus.Text = $"Encryption complete! Speed: {speed:F4} GB/s, Processed: {sizeStr} in {seconds:F2} s. At this speed, 1GB would take {estTime1GB:F2} s.";
            }
            catch (Exception ex)
            {
                EncryptionStatus.Text = $"Error: {ex.Message}";
            }
            finally
            {
                EncryptButton.IsEnabled = true;
                EncryptionProgress.IsVisible = false;
            }
        }

        private async void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            var EncryptedFolderTextBox = this.FindControl<TextBox>("EncryptedFolderTextBox");
            var DecryptedFolderTextBox = this.FindControl<TextBox>("DecryptedFolderTextBox");
            var DecryptKeyDirTextBox = this.FindControl<TextBox>("DecryptKeyDirTextBox");
            var DecryptButton = this.FindControl<Button>("DecryptButton");
            var DecryptionProgress = this.FindControl<ProgressBar>("DecryptionProgress");
            var DecryptionStatus = this.FindControl<TextBlock>("DecryptionStatus");
            var UseLocalKeysRadio = this.FindControl<RadioButton>("UseLocalKeysRadio");
            var UseTPMKeysRadio = this.FindControl<RadioButton>("UseTPMKeysRadio");
            var UseAWSKeysRadio = this.FindControl<RadioButton>("UseAWSKeysRadio");
            var UseHybridKeysRadio = this.FindControl<RadioButton>("UseHybridKeysRadio");

            if (UseTPMKeysRadio.IsChecked == true)
            {
                if (string.IsNullOrWhiteSpace(EncryptedFolderTextBox.Text) || 
                    string.IsNullOrWhiteSpace(DecryptedFolderTextBox.Text))
                {
                    DecryptionStatus.Text = "Please fill in all required fields.";
                    return;
                }
                DecryptButton.IsEnabled = false;
                DecryptionProgress.IsVisible = true;
                DecryptionProgress.IsIndeterminate = true;
                DecryptionStatus.Text = "Decrypting with TPM...";
                try
                {
                    string inputFolder = EncryptedFolderTextBox.Text;
                    string outputFolder = DecryptedFolderTextBox.Text;
                    if (!Directory.Exists(outputFolder))
                        Directory.CreateDirectory(outputFolder);
                    var files = Directory.GetFiles(inputFolder, "*.enc");
                    int total = files.Length;
                    int count = 0;
                    var stopwatch = new Stopwatch();
                    long totalBytes = 0;
                    stopwatch.Start();
                    foreach (var file in files)
                    {
                        string fileName = Path.GetFileNameWithoutExtension(file);
                        string outFile = Path.Combine(outputFolder, fileName);
                        try
                        {
                            await Task.Run(() => TpmDecryptionService.DecryptFileWithTpm(file, outFile));
                        }
                        catch (NotImplementedException nie)
                        {
                            DecryptionStatus.Text = nie.Message;
                            break;
                        }
                        count++;
                        totalBytes += new FileInfo(file).Length;
                        DecryptionStatus.Text = $"Decrypted {count}/{total} files (TPM).";
                    }
                    stopwatch.Stop();
                    double seconds = stopwatch.Elapsed.TotalSeconds;
                    double gb = totalBytes / 1_073_741_824.0;
                    double speed = seconds > 0 ? gb / seconds : 0;
                    double estTime1GB = speed > 0 ? 1.0 / speed : 0;
                    string sizeStr = totalBytes >= 1_073_741_824 ? $"{gb:F2} GB" :
                                     totalBytes >= 1_048_576 ? $"{totalBytes / 1_048_576.0:F2} MB" :
                                     $"{totalBytes / 1024.0:F2} KB";
                    if (count == total)
                        DecryptionStatus.Text = $"TPM decryption complete! Speed: {speed:F4} GB/s, Processed: {sizeStr} in {seconds:F2} s. At this speed, 1GB would take {estTime1GB:F2} s.";
                }
                catch (Exception ex)
                {
                    DecryptionStatus.Text = $"Error: {ex.Message}";
                }
                finally
                {
                    DecryptButton.IsEnabled = true;
                    DecryptionProgress.IsVisible = false;
                }
                return;
            }

            if (UseLocalKeysRadio.IsChecked != true)
            {
                await ShowMessageAsync("Only 'Use local keys' and 'Use TPM keys' decryption are supported in this build. Please select 'Use local keys' or 'Use TPM keys'.");
                return;
            }

            if (string.IsNullOrWhiteSpace(EncryptedFolderTextBox.Text) || 
                string.IsNullOrWhiteSpace(DecryptedFolderTextBox.Text))
            {
                DecryptionStatus.Text = "Please fill in all required fields.";
                return;
            }

            DecryptButton.IsEnabled = false;
            DecryptionProgress.IsVisible = true;
            DecryptionProgress.IsIndeterminate = true;
            DecryptionStatus.Text = "Decrypting...";

            var stopwatchDec = new Stopwatch();
            long totalBytesDec = 0;
            try
            {
                string inputFolder = EncryptedFolderTextBox.Text;
                string outputFolder = DecryptedFolderTextBox.Text;
                string keyDir = DecryptKeyDirTextBox.Text;
                if (!Directory.Exists(outputFolder))
                    Directory.CreateDirectory(outputFolder);

                var files = Directory.GetFiles(inputFolder, "*.enc");
                int total = files.Length;
                int count = 0;
                stopwatchDec.Start();
                foreach (var file in files)
                {
                    string fileName = Path.GetFileNameWithoutExtension(file);
                    string outFile = Path.Combine(outputFolder, fileName);
                    byte[] key = null;
                    if (!string.IsNullOrWhiteSpace(keyDir))
                    {
                        string keyFilePath = Path.Combine(keyDir, fileName + ".key");
                        if (File.Exists(keyFilePath))
                        {
                            key = File.ReadAllBytes(keyFilePath);
                        }
                        else
                        {
                            var keyInput = await ShowInputDialogAsync($"Key file not found for {fileName}. Enter 32-byte key (hex):");
                            if (string.IsNullOrWhiteSpace(keyInput))
                            {
                                DecryptionStatus.Text = "Decryption cancelled: No key provided.";
                                return;
                            }
                            key = Convert.FromHexString(keyInput);
                        }
                    }
                    else
                    {
                        var keyInput = await ShowInputDialogAsync("Enter 32-byte key (hex) for decryption:");
                        if (string.IsNullOrWhiteSpace(keyInput))
                        {
                            DecryptionStatus.Text = "Decryption cancelled: No key provided.";
                            return;
                        }
                        key = Convert.FromHexString(keyInput);
                    }
                    long fileSize = new FileInfo(file).Length;
                    await Task.Run(() => EncryptionService.DecryptFile(file, outFile, key));
                    totalBytesDec += fileSize;
                    count++;
                    DecryptionStatus.Text = $"Decrypted {count}/{total} files.";
                }
                stopwatchDec.Stop();
                double seconds = stopwatchDec.Elapsed.TotalSeconds;
                double gb = totalBytesDec / 1_073_741_824.0;
                double speed = seconds > 0 ? gb / seconds : 0;
                double estTime1GB = speed > 0 ? 1.0 / speed : 0;
                string sizeStr = totalBytesDec >= 1_073_741_824 ? $"{gb:F2} GB" :
                                 totalBytesDec >= 1_048_576 ? $"{totalBytesDec / 1_048_576.0:F2} MB" :
                                 $"{totalBytesDec / 1024.0:F2} KB";
                DecryptionStatus.Text = $"Decryption complete! Speed: {speed:F4} GB/s, Processed: {sizeStr} in {seconds:F2} s. At this speed, 1GB would take {estTime1GB:F2} s.";
            }
            catch (Exception ex)
            {
                DecryptionStatus.Text = $"Error: {ex.Message}";
            }
            finally
            {
                DecryptButton.IsEnabled = true;
                DecryptionProgress.IsVisible = false;
            }
        }

        private async void GenerateRSAButton_Click(object sender, RoutedEventArgs e)
        {
            var KeyOutputDirTextBox = this.FindControl<TextBox>("KeyOutputDirTextBox");

            if (string.IsNullOrWhiteSpace(KeyOutputDirTextBox.Text))
            {
                await ShowMessageAsync("Please specify a key output directory.");
                return;
            }

            try
            {
                await Task.Run(() =>
                {
                    string scriptCommand = $"exec(open(r'{PythonScriptPath}').read()); " +
                        $"generate_rsa_keys(r'{Path.Combine(KeyOutputDirTextBox.Text, "private.pem")}', " +
                        $"r'{Path.Combine(KeyOutputDirTextBox.Text, "public.pem")}')";
                        
                    ExecutePythonScript("-c", scriptCommand);
                });

                await ShowMessageAsync("RSA keys generated successfully.");
            }
            catch (Exception ex)
            {
                await ShowMessageAsync($"Error: {ex.Message}");
            }
        }

        private async void StoreKeyButton_Click(object sender, RoutedEventArgs e)
        {
            var AWSKeyDirTextBox = this.FindControl<TextBox>("AWSKeyDirTextBox");
            var StoreKeySecretNameTextBox = this.FindControl<TextBox>("StoreKeySecretNameTextBox");
            var KeyManagementRegionTextBox = this.FindControl<TextBox>("KeyManagementRegionTextBox");

            if (string.IsNullOrWhiteSpace(AWSKeyDirTextBox.Text) || 
                string.IsNullOrWhiteSpace(StoreKeySecretNameTextBox.Text))
            {
                await ShowMessageAsync("Please fill in all required fields.");
                return;
            }

            try
            {
                await Task.Run(() =>
                {
                    string scriptCommand = $"exec(open(r'{PythonScriptPath}').read()); " +
                        $"store_rsa_keys_in_aws_secret_manager(r'{AWSKeyDirTextBox.Text}', " +
                        $"'{StoreKeySecretNameTextBox.Text}', '{KeyManagementRegionTextBox.Text}')";
                        
                    ExecutePythonScript("-c", scriptCommand);
                });

                await ShowMessageAsync("RSA key stored in AWS successfully.");
            }
            catch (Exception ex)
            {
                await ShowMessageAsync($"Error: {ex.Message}");
            }
        }

        private async void StoreSharesButton_Click(object sender, RoutedEventArgs e)
        {
            var KeySharesDirTextBox = this.FindControl<TextBox>("KeySharesDirTextBox");
            var StoreSharesSecretNameTextBox = this.FindControl<TextBox>("StoreSharesSecretNameTextBox");
            var KeyManagementRegionTextBox = this.FindControl<TextBox>("KeyManagementRegionTextBox");

            if (string.IsNullOrWhiteSpace(KeySharesDirTextBox.Text) || 
                string.IsNullOrWhiteSpace(StoreSharesSecretNameTextBox.Text))
            {
                await ShowMessageAsync("Please fill in all required fields.");
                return;
            }

            try
            {
                await Task.Run(() =>
                {
                    string scriptCommand = $"exec(open(r'{PythonScriptPath}').read()); " +
                        $"store_key_shares_in_aws_secret_manager(r'{KeySharesDirTextBox.Text}', " +
                        $"'{StoreSharesSecretNameTextBox.Text}', '{KeyManagementRegionTextBox.Text}')";
                        
                    ExecutePythonScript("-c", scriptCommand);
                });

                await ShowMessageAsync("Key shares stored in AWS successfully.");
            }
            catch (Exception ex)
            {
                await ShowMessageAsync($"Error: {ex.Message}");
            }
        }

        private async void RetrieveKeyButton_Click(object sender, RoutedEventArgs e)
        {
            var RetrieveOutputDirTextBox = this.FindControl<TextBox>("RetrieveOutputDirTextBox");
            var RetrieveKeySecretTextBox = this.FindControl<TextBox>("RetrieveKeySecretTextBox");
            var KeyManagementRegionTextBox = this.FindControl<TextBox>("KeyManagementRegionTextBox");

            if (string.IsNullOrWhiteSpace(RetrieveOutputDirTextBox.Text) || 
                string.IsNullOrWhiteSpace(RetrieveKeySecretTextBox.Text))
            {
                await ShowMessageAsync("Please fill in all required fields.");
                return;
            }

            try
            {
                await Task.Run(() =>
                {
                    string scriptCommand = $"exec(open(r'{PythonScriptPath}').read()); " +
                        $"retrieve_rsa_key_from_aws('{RetrieveKeySecretTextBox.Text}', " +
                        $"'{KeyManagementRegionTextBox.Text}', r'{RetrieveOutputDirTextBox.Text}')";
                        
                    ExecutePythonScript("-c", scriptCommand);
                });

                await ShowMessageAsync("RSA key retrieved from AWS successfully.");
            }
            catch (Exception ex)
            {
                await ShowMessageAsync($"Error: {ex.Message}");
            }
        }

        private async void RetrieveSharesButton_Click(object sender, RoutedEventArgs e)
        {
            var RetrieveOutputDirTextBox = this.FindControl<TextBox>("RetrieveOutputDirTextBox");
            var RetrieveSharesSecretTextBox = this.FindControl<TextBox>("RetrieveSharesSecretTextBox");
            var KeyManagementRegionTextBox = this.FindControl<TextBox>("KeyManagementRegionTextBox");

            if (string.IsNullOrWhiteSpace(RetrieveOutputDirTextBox.Text) || 
                string.IsNullOrWhiteSpace(RetrieveSharesSecretTextBox.Text))
            {
                await ShowMessageAsync("Please fill in all required fields.");
                return;
            }

            try
            {
                await Task.Run(() =>
                {
                    string scriptCommand = $"exec(open(r'{PythonScriptPath}').read()); " +
                        $"retrieve_key_shares_from_aws('{RetrieveSharesSecretTextBox.Text}', " +
                        $"'{KeyManagementRegionTextBox.Text}', r'{Path.Combine(RetrieveOutputDirTextBox.Text, "key_shares")}')";
                        
                    ExecutePythonScript("-c", scriptCommand);
                });

                await ShowMessageAsync("Key shares retrieved from AWS successfully.");
            }
            catch (Exception ex)
            {
                await ShowMessageAsync($"Error: {ex.Message}");
            }
        }

        private async void DeleteLocalKeysButton_Click(object sender, RoutedEventArgs e)
        {
            var DeleteKeysDirTextBox = this.FindControl<TextBox>("DeleteKeysDirTextBox");

            if (string.IsNullOrWhiteSpace(DeleteKeysDirTextBox.Text))
            {
                await ShowMessageAsync("Please specify a key directory to clean.");
                return;
            }

            var result = await ShowConfirmDialogAsync(
                "Are you sure you want to delete all local keys? This action cannot be undone.");

            if (result)
            {
                try
                {
                    await Task.Run(() =>
                    {
                        string scriptCommand = $"exec(open(r'{PythonScriptPath}').read()); " +
                            $"delete_local_keys(r'{DeleteKeysDirTextBox.Text}')";
                            
                        ExecutePythonScript("-c", scriptCommand);
                    });

                    await ShowMessageAsync("Local keys deleted successfully.");
                }
                catch (Exception ex)
                {
                    await ShowMessageAsync($"Error: {ex.Message}");
                }
            }
        }
        
        private void ExecutePythonScript(params string[] arguments)
        {
            ProcessStartInfo start = new ProcessStartInfo
            {
                FileName = "python",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            foreach (var argument in arguments)
            {
                start.ArgumentList.Add(argument);
            }

            using Process process = new Process { StartInfo = start };
            StringBuilder output = new StringBuilder();
            StringBuilder error = new StringBuilder();

            process.OutputDataReceived += (sender, e) => {
                if (e.Data != null)
                {
                    output.AppendLine(e.Data);
                    Console.WriteLine(e.Data); // For debugging
                }
            };

            process.ErrorDataReceived += (sender, e) => {
                if (e.Data != null)
                {
                    error.AppendLine(e.Data);
                    Console.WriteLine($"ERROR: {e.Data}"); // For debugging
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                throw new Exception($"Python script error: {error}");
            }
        }

        private async Task ShowMessageAsync(string message)
        {
            await MessageBox.Show(this, message, "Information", MessageBox.MessageBoxButtons.Ok);
        }

        private async Task<bool> ShowConfirmDialogAsync(string message)
        {
            var result = await MessageBox.Show(this, message, "Confirm", 
                MessageBox.MessageBoxButtons.YesNo);
            return result == MessageBox.MessageBoxResult.Yes;
        }

        private async Task<string> ShowInputDialogAsync(string message)
        {
            var dialog = new Window
            {
                Title = "Input Required",
                Width = 400,
                Height = 150,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false
            };
            var mainPanel = new StackPanel { Margin = new Thickness(15) };
            mainPanel.Children.Add(new TextBlock { Text = message, Margin = new Thickness(0, 0, 0, 10) });
            var inputBox = new TextBox { Width = 350 };
            mainPanel.Children.Add(inputBox);
            var buttonPanel = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right, Spacing = 10 };
            var okButton = new Button { Content = "OK", Width = 80 };
            var cancelButton = new Button { Content = "Cancel", Width = 80 };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            mainPanel.Children.Add(buttonPanel);
            dialog.Content = mainPanel;
            var tcs = new TaskCompletionSource<string>();
            okButton.Click += (_, __) => { tcs.SetResult(inputBox.Text); dialog.Close(); };
            cancelButton.Click += (_, __) => { tcs.SetResult(""); dialog.Close(); };
            await dialog.ShowDialog(this);
            return await tcs.Task;
        }
    }

    // Simple message box implementation since Avalonia doesn't have a built-in one
    public class MessageBox
    {
        public enum MessageBoxButtons
        {
            Ok,
            YesNo
        }

        public enum MessageBoxResult
        {
            Ok,
            Yes,
            No
        }

        public static async Task<MessageBoxResult> Show(Window parent, string text, string title, MessageBoxButtons buttons)
        {
            var msgbox = new Window
            {
                Title = title,
                Width = 400,
                Height = 150,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false
            };

            var mainPanel = new StackPanel
            {
                Margin = new Thickness(15),
                VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
            };

            mainPanel.Children.Add(new TextBlock
            {
                Text = text,
                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 15)
            });

            var buttonPanel = new StackPanel
            {
                Orientation = Avalonia.Layout.Orientation.Horizontal,
                HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
                Spacing = 10
            };

            var tcs = new TaskCompletionSource<MessageBoxResult>();

            if (buttons == MessageBoxButtons.Ok)
            {
                var okButton = new Button { Content = "OK", Width = 80 };
                okButton.Click += (_, __) =>
                {
                    tcs.SetResult(MessageBoxResult.Ok);
                    msgbox.Close();
                };
                buttonPanel.Children.Add(okButton);
            }
            else
            {
                var yesButton = new Button { Content = "Yes", Width = 80 };
                yesButton.Click += (_, __) =>
                {
                    tcs.SetResult(MessageBoxResult.Yes);
                    msgbox.Close();
                };

                var noButton = new Button { Content = "No", Width = 80 };
                noButton.Click += (_, __) =>
                {
                    tcs.SetResult(MessageBoxResult.No);
                    msgbox.Close();
                };

                buttonPanel.Children.Add(yesButton);
                buttonPanel.Children.Add(noButton);
            }

            mainPanel.Children.Add(buttonPanel);
            msgbox.Content = mainPanel;

            // Set owner and show dialog
            if (parent != null)
            {
                msgbox.ShowDialog(parent);
            }
            else
            {
                msgbox.Show();
            }

            return await tcs.Task;
        }
    }
}
