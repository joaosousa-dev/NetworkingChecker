using PacketDotNet;
using SharpPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;

namespace NetworkingChecker
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private HashSet<string> knownIPAddresses = new HashSet<string>();
        private Dictionary<string, DateTime> lastSeenDevices = new Dictionary<string, DateTime>();

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {

            _logger.LogInformation("Iniciando captura de pacotes...");

            // Abre a interface de rede para captura de pacotes
            var devices = CaptureDeviceList.Instance.ToList();

            var device = devices.FirstOrDefault(x => x.Name.Contains("rpcap://\\Device\\NPF_{0B35CBB6-0F68-4DD0-8650-91ADF420BEE3}"));

            if (device == null)
            {
                _logger.LogError("Nenhuma interface de rede encontrada para captura de pacotes.");
                return;
            }

            // Abre a interface de rede para captura de pacotes
            device.Open(DeviceMode.Promiscuous);
            device.Filter = "arp";


            // Registra o manipulador de eventos de pacotes
            device.OnPacketArrival += (sender, e) =>
            {
                // Processa o pacote capturado
                PacketHandler(Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data));
            };

            // Começa a captura de pacotes
            device.StartCapture();

            // Aguarda a solicitação de cancelamento
            while (!stoppingToken.IsCancellationRequested)
            {

                Task.Delay(1000).Wait();
            }

            // Para a captura de pacotes
            device.StopCapture();
            device.Close();

            _logger.LogInformation("Parando captura de pacotes.");

        }

        // Método para processar cada pacote capturado
        private void PacketHandler(Packet packet)
        {
            if (packet.PayloadPacket is ARPPacket arpPacket)
            {
                string sourceIpAddress = arpPacket.SenderProtocolAddress.ToString();
                string MacAddress = arpPacket.SenderHardwareAddress.ToString();
                lastSeenDevices[MacAddress] = DateTime.Now;

                // Verifica se o endereço IP é novo
                if (!knownIPAddresses.Contains(MacAddress))
                {
                    _logger.LogInformation($"{DateTime.Now} - Novo dispositivo conectado: MAC = {MacAddress} , IP = {sourceIpAddress}");
                    knownIPAddresses.Add(MacAddress);
                }
                else if (knownIPAddresses.Contains(MacAddress) && (DateTime.Now - lastSeenDevices[MacAddress]) > TimeSpan.FromMinutes(5))
                {
                    _logger.LogInformation($"{DateTime.Now} - Dispositivo reconectou: MAC = {MacAddress} , IP = {sourceIpAddress}");
                }
            }

        }


    }
}
