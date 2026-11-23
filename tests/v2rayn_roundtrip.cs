// Copy into a console project referencing v2rayN 7.25.6 ServiceLib.csproj.
// Arguments: generated Base64 v2.log, output directory. Does not start the UI/core.
using System.Reflection;
using System.Text.Json;
using ServiceLib.Common;
using ServiceLib.Enums;
using ServiceLib.Handler.Fmt;
using ServiceLib.Handler;
using ServiceLib.Models.Configs;
using ServiceLib.Models.CoreConfigs;
using ServiceLib.Services.CoreConfig;

var decoded = Utils.Base64Decode(File.ReadAllText(args[0]));
var original = InnerFmt.Resolve(decoded, "fixture")!;
if (original.Count != 2) throw new Exception("Native PEM profiles missing");
foreach (var line in decoded.Split('\n', StringSplitOptions.RemoveEmptyEntries))
{
    if (line.StartsWith("v2rayn://")) continue;
    var item = FmtHandler.ResolveConfig(line, out var error) ?? throw new Exception(error);
    original.Add(item);
}
if (original.Count != 5) throw new Exception("Mixed Base64 import did not preserve five profiles");
var importConfig = new Config { CoreBasicItem = new CoreBasicItem(), HysteriaItem = new HysteriaItem() };
foreach (var node in original)
{
    // The real subscription importer applies these defaults after resolving a URI.
    if (node.ConfigType == EConfigType.TUIC) await ConfigHandler.AddTuicServer(importConfig, node, false);
    if (node.ConfigType == EConfigType.Hysteria2) await ConfigHandler.AddHysteria2Server(importConfig, node, false);
}
var exported = InnerFmt.ToUri(original)!;
var imported = InnerFmt.Resolve(exported, "fixture-reimport")!;
Directory.CreateDirectory(args[1]);
foreach (var node in imported)
{
    if (node.ConfigType is not (EConfigType.TUIC or EConfigType.Hysteria2)) continue;
    var before = original.Single(n => n.ConfigType == node.ConfigType && n.Remarks == node.Remarks);
    var legacy = before.GetAllowInsecure();
    if (!legacy && (node.Cert != before.Cert || !node.Cert.Contains("BEGIN CERTIFICATE")))
        throw new Exception("Certificate lost in import/export/reimport");
    if (node.GetAllowInsecure() != legacy) throw new Exception("Verification mode changed after reimport");
    var config = new Config { CoreBasicItem = new CoreBasicItem(), HysteriaItem = new HysteriaItem() };
    var context = new CoreConfigContext { Node=node, AppConfig=config, RunCoreType=ECoreType.sing_box };
    var service = new CoreConfigSingboxService(context);
    var method = typeof(CoreConfigSingboxService).GetMethod("BuildProxyServer", BindingFlags.NonPublic|BindingFlags.Instance)!;
    var outbound = (Outbound4Sbox)method.Invoke(service, null)!;
    if (outbound.tls?.enabled != true || outbound.tls.insecure != legacy || (!legacy && outbound.tls.certificate?.Count != 1))
        throw new Exception("PEM not applied to generated sing-box TLS configuration");
    if (outbound.tls.server_name != node.Sni) throw new Exception("SNI changed");
    File.WriteAllText(Path.Combine(args[1],node.ConfigType+(legacy?"-legacy":"")+".json"),JsonUtils.Serialize(outbound));
    Console.WriteLine("PASS: "+node.ConfigType+(legacy?" legacy":" PEM")+" mixed Base64 import, export/reimport and real sing-box outbound generation");
}
