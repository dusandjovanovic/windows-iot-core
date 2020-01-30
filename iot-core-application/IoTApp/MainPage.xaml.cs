using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.Devices.Enumeration;
using Windows.Devices.Gpio;
using Windows.Foundation;
using Windows.Graphics.Display;
using Windows.Media.Capture;
using Windows.Media.Core;
using Windows.Media.MediaProperties;
using Windows.UI.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media;

namespace IoTApp
{
    public sealed partial class MainPage : Page
    {
        MediaCaptureInitializationSettings captureInitSettings;
        List<DeviceInformation> deviceList;
        IList<GpioPin> pinsList;
        MediaEncodingProfile profile;

        public MediaCapture mediaCapture;
        private FaceDetectionEffect faceDetectionEffect;
        public bool isRecording;
        public string fileName;

        private int DEVICE_PIN_ID = 17;

        public MainPage()
        {
            this.InitializeComponent();
            EnumerateCameras();
            EnumerateHardware();
        }

        private async Task StartMediaCaptureSession()
        {
            await StopMediaCaptureSession();

            var storageFile = await Windows.Storage.KnownFolders.VideosLibrary.CreateFileAsync("_video.wmv", Windows.Storage.CreationCollisionOption.GenerateUniqueName);
            fileName = storageFile.Name;

            await mediaCapture.StartRecordToStorageFileAsync(profile, storageFile);
            await mediaCapture.StartPreviewAsync();
            isRecording = true;
        }

        private async Task StopMediaCaptureSession()
        {
            if (isRecording)
            {
                faceDetectionEffect.Enabled = false;
                faceDetectionEffect.FaceDetected -= FaceDetectionEffect_FaceDetected;
                await mediaCapture.ClearEffectsAsync(MediaStreamType.VideoPreview);
                await mediaCapture.StopPreviewAsync();
                await mediaCapture.StopRecordAsync();
                isRecording = false;
                faceDetectionEffect = null;
            }
        }

        private async void EnumerateCameras()
        {
            var devices = await Windows.Devices.Enumeration.DeviceInformation.FindAllAsync(Windows.Devices.Enumeration.DeviceClass.VideoCapture);
            deviceList = new List<Windows.Devices.Enumeration.DeviceInformation>();

            if (devices.Count > 0)
            {
                for (var i = 0; i < devices.Count; i++)
                {
                    deviceList.Add(devices[i]);
                }
                InitCaptureSettings();
                InitMediaCapture();
            }
        }

        private void EnumerateHardware()
        {
            pinsList = new List<GpioPin>();
            var gpio = GpioController.GetDefault();

            if (gpio == null)
            {
                Debug.WriteLine("GPIO controller is missing!");
                return;
            }

            pinsList.Add(gpio.OpenPin(DEVICE_PIN_ID));

            foreach (var pin in pinsList)
            {
                pin.Write(GpioPinValue.Low);
                pin.SetDriveMode(GpioPinDriveMode.Output);
            }
        }

        private void ActuateHardware()
        {
            try
            {
                var ledDiode = pinsList[0];
                ledDiode.Write(GpioPinValue.High);

                Task.Delay(2 * 1000).Wait();

                foreach (var pin in pinsList)
                {
                    pin.Write(GpioPinValue.Low);
                }
            }
            catch (Exception deviceError)
            {
                Debug.WriteLine(deviceError.ToString());
            }
        }

        private void InitCaptureSettings()
        {
            captureInitSettings = new Windows.Media.Capture.MediaCaptureInitializationSettings();
            captureInitSettings.AudioDeviceId = "";
            captureInitSettings.VideoDeviceId = "";
            captureInitSettings.StreamingCaptureMode = Windows.Media.Capture.StreamingCaptureMode.AudioAndVideo;
            captureInitSettings.PhotoCaptureSource = Windows.Media.Capture.PhotoCaptureSource.VideoPreview;

            if (deviceList.Count > 0)
            {
                captureInitSettings.VideoDeviceId = deviceList[0].Id;
            }
        }

        private async void InitMediaCapture()
        {
            mediaCapture = new Windows.Media.Capture.MediaCapture();
            await mediaCapture.InitializeAsync(captureInitSettings);

            Windows.Media.Effects.VideoEffectDefinition def = new Windows.Media.Effects.VideoEffectDefinition(Windows.Media.VideoEffects.VideoStabilization);
            await mediaCapture.AddVideoEffectAsync(def, MediaStreamType.VideoRecord);

            profile = Windows.Media.MediaProperties.MediaEncodingProfile.CreateMp4(Windows.Media.MediaProperties.VideoEncodingQuality.Qvga);
            System.Guid MFVideoRotationGuild = new System.Guid("C380465D-2271-428C-9B83-ECEA3B4A85C1");
            int MFVideoRotation = ConvertVideoRotationToMFRotation(VideoRotation.None);
            profile.Video.Properties.Add(MFVideoRotationGuild, PropertyValue.CreateInt32(MFVideoRotation));
            var transcoder = new Windows.Media.Transcoding.MediaTranscoder();
            transcoder.AddVideoEffect(Windows.Media.VideoEffects.VideoStabilization);
            capturePreview.Source = mediaCapture;
            DisplayInformation.AutoRotationPreferences = DisplayOrientations.None;

            var definition = new FaceDetectionEffectDefinition();
            definition.SynchronousDetectionEnabled = false;
            definition.DetectionMode = FaceDetectionMode.HighPerformance;
            faceDetectionEffect = (FaceDetectionEffect)await mediaCapture.AddVideoEffectAsync(definition, MediaStreamType.VideoPreview);
            faceDetectionEffect.DesiredDetectionInterval = TimeSpan.FromMilliseconds(33);
            faceDetectionEffect.Enabled = true;
            faceDetectionEffect.FaceDetected += FaceDetectionEffect_FaceDetected;
        }

        private int ConvertVideoRotationToMFRotation(VideoRotation rotation)
        {
            int MFVideoRotation = 0;
            switch (rotation)
            {
                case VideoRotation.Clockwise90Degrees:
                    MFVideoRotation = 90;
                    break;
                case VideoRotation.Clockwise180Degrees:
                    MFVideoRotation = 180;
                    break;
                case VideoRotation.Clockwise270Degrees:
                    MFVideoRotation = 270;
                    break;
            }
            return MFVideoRotation;
        }

        private void FaceDetectionEffect_FaceDetected(FaceDetectionEffect sender, FaceDetectedEventArgs args)
        {
            foreach (Windows.Media.FaceAnalysis.DetectedFace face in args.ResultFrame.DetectedFaces)
            {
                _ = Dispatcher.RunAsync(CoreDispatcherPriority.Normal, () => {
                    txtFaceDetected.Text = "Face has been detected!";
                    txtFaceDetected.FontWeight = Windows.UI.Text.FontWeights.Bold;
                    txtFaceDetected.Foreground = new SolidColorBrush(Windows.UI.Colors.SteelBlue);
                    ActuateHardware();
                });
            }
        }

        private async void startCapture(object sender, RoutedEventArgs e)
        {
            await StartMediaCaptureSession();
        }

        private async void stopCapture(object sender, RoutedEventArgs e)
        {
            await StopMediaCaptureSession();
        }
    }
}
