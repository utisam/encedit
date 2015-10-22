using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.ApplicationModel.Resources;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.Storage.Provider;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace encedit
{
    public sealed partial class MainPage : Page
    {

        static readonly string ALGORITHM_NAME = SymmetricAlgorithmNames.AesCbcPkcs7;
        const uint keyLength = 32;

        public MainPage()
        {
            this.InitializeComponent();
        }

        private void initControlls()
        {
            var loader = ResourceLoader.GetForCurrentView();
            initControlls(loader.GetString("NewFile"), "");
        }

        private void initControlls(string headdingText, string contentText)
        {
            SavePassword.Password = "";
            PassConferm.Password = "";
            IncorrectSavePassMsg.Visibility = Visibility.Collapsed;

            Headding.Text = headdingText;
            ContentText.Text = contentText;

            OpenPassword.Password = "";
            IncorrectOpenPassMsg.Visibility = Visibility.Collapsed;
        }

        // Save

        private async void saveButtonClick(object sender, RoutedEventArgs e)
        {
            if (SavePassword.Password == "" || SavePassword.Password != PassConferm.Password)
            {
                IncorrectSavePassMsg.Visibility = Visibility.Visible;
                return;
            }
            IncorrectSavePassMsg.Visibility = Visibility.Collapsed;

            StorageFile file = await pickupSaveFile();
            if (file != null)
            {
                // Prevent updates to the remote version of the file until we finish making changes and call CompleteUpdatesAsync.
                CachedFileManager.DeferUpdates(file);

                // write to file
                IBuffer salt = null, iv = null;
                IBuffer body = toEncryptedBuffer(toCompressedBuffer(ContentText.Text), SavePassword.Password, out salt, out iv);

                var buffer = new Windows.Storage.Streams.Buffer(salt.Length + iv.Length + body.Length);
                salt.CopyTo(0, buffer, 0, salt.Length);
                iv.CopyTo(0, buffer, salt.Length, iv.Length);
                body.CopyTo(0, buffer, salt.Length + iv.Length, body.Length);
                buffer.Length = salt.Length + iv.Length + body.Length;
                await FileIO.WriteBufferAsync(file, buffer);

                // Let Windows know that we're finished changing the file so the other app can update the remote version of the file.
                // Completing updates may require Windows to ask for user input.
                FileUpdateStatus status = await CachedFileManager.CompleteUpdatesAsync(file);
                if (status == FileUpdateStatus.Complete)
                {
                    Headding.Text = file.Name;
                }
                else
                {
                    // cannot not saved
                }
            }

        }

        private IBuffer toEncryptedBuffer(IBuffer buffer, string rawPassword, out IBuffer salt, out IBuffer iv)
        {
            // https://msdn.microsoft.com/en-us/library/windows/apps/windows.security.cryptography.core.symmetrickeyalgorithmprovider.aspx
            SymmetricKeyAlgorithmProvider algorithm = SymmetricKeyAlgorithmProvider.OpenAlgorithm(ALGORITHM_NAME);

            salt = CryptographicBuffer.GenerateRandom(32);
            var derviedKey = createDerviedKey(algorithm, rawPassword, salt);

            iv = CryptographicBuffer.GenerateRandom(algorithm.BlockLength);

            return CryptographicEngine.Encrypt(derviedKey, buffer, iv);
        }

        private IBuffer toCompressedBuffer(string text)
        {
            var memoryStream = new MemoryStream();

            using (var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress)))
            {
                writer.Write(text);
            }

            return memoryStream.ToArray().AsBuffer();
        }

        private async Task<StorageFile> pickupSaveFile()
        {
            var loader = ResourceLoader.GetForCurrentView();
            var savePicker = new FileSavePicker();

            savePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            savePicker.FileTypeChoices.Add(loader.GetString("EncryptedPlainText"), new List<string>() { ".etxt" });
            savePicker.SuggestedFileName = loader.GetString("SuggestedFileName");
            return await savePicker.PickSaveFileAsync();
        }

        // Open

        private StorageFile openFile = null;

        private async void openButtonClick(object sender, RoutedEventArgs e)
        {
            openFile = await pickupOpenFile();
            if (openFile != null)
            {
                OpenPasswordFlyout.ShowAt(sender as FrameworkElement);
            }
        }

        private async void openOkButtonClick(object sender, RoutedEventArgs e)
        {
            if (openFile != null)
            {
                IBuffer buffer = await FileIO.ReadBufferAsync(openFile);
                try
                {
                    initControlls(openFile.Name, toDecompressedText(toDecryptedBuffer(buffer, OpenPassword.Password)));
                    OpenPasswordFlyout.Hide();
                    OpenPassword.Password = "";
                    IncorrectOpenPassMsg.Visibility = Visibility.Collapsed;
                }
                catch (Exception _)
                {
                    IncorrectOpenPassMsg.Visibility = Visibility.Visible;
                }
            }
        }

        private string toDecompressedText(IBuffer buffer)
        {
            var reader = new StreamReader(new DeflateStream(buffer.AsStream(), CompressionMode.Decompress));
            return reader.ReadToEnd();
        }

        private IBuffer toDecryptedBuffer(IBuffer buffer, string rawPassword)
        {
            SymmetricKeyAlgorithmProvider algorithm = SymmetricKeyAlgorithmProvider.OpenAlgorithm(ALGORITHM_NAME);
            byte[] bufferArray = buffer.ToArray();

            IBuffer salt = bufferArray.SubArray(0, 32).AsBuffer();
            var derviedKey = createDerviedKey(algorithm, rawPassword, salt);

            int blockLength = (int)algorithm.BlockLength;
            IBuffer iv = bufferArray.SubArray(32, blockLength).AsBuffer();

            IBuffer body = bufferArray.SubArray(32 + blockLength, bufferArray.Length - (32 + blockLength)).AsBuffer();
            return CryptographicEngine.Decrypt(derviedKey, body, iv);
        }

        private async Task<StorageFile> pickupOpenFile()
        {
            var openPicker = new FileOpenPicker();

            openPicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            openPicker.FileTypeFilter.Add(".etxt");
            return await openPicker.PickSingleFileAsync();
        }

        private CryptographicKey createDerviedKey(SymmetricKeyAlgorithmProvider algorithm, string rawPassword, IBuffer salt)
        {
            KeyDerivationAlgorithmProvider pbkdf2 = KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithmNames.Pbkdf2Sha256);
            IBuffer passwordBuffer = CryptographicBuffer.ConvertStringToBinary(rawPassword, BinaryStringEncoding.Utf8);
            CryptographicKey key = pbkdf2.CreateKey(passwordBuffer);

            KeyDerivationParameters parameters = KeyDerivationParameters.BuildForPbkdf2(salt, 10000);

            IBuffer derviedKeyMaterial = CryptographicEngine.DeriveKeyMaterial(key, parameters, 32);
            return algorithm.CreateSymmetricKey(derviedKeyMaterial);
        }

        private void newButtonClick(object sender, RoutedEventArgs e)
        {
            initControlls();
        }

        private void openCancelButtonClick(object sender, RoutedEventArgs e)
        {
            OpenPasswordFlyout.Hide();
            OpenPassword.Password = "";
            IncorrectOpenPassMsg.Visibility = Visibility.Collapsed;
        }
    }

    public static class ArrayExtension
    {
        public static T[] SubArray<T>(this T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }
    }
}
