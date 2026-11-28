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
var notices = original.Where(n => n.Remarks.StartsWith("[NOTICE]") || n.Remarks.StartsWith("[提醒]")).ToList();
if (notices.Count is not (0 or 2) || original.Count != 5 + notices.Count)
    throw new Exception("Mixed Base64 import did not preserve profiles and bilingual notices");
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
foreach (var notice in notices)
{
    var node = imported.Single(n => n.Remarks == notice.Remarks);
    if (node.Address != notice.Address || !node.Address.EndsWith(".invalid") || node.Port != 1 ||
        node.ConfigType != EConfigType.VLESS || node.GetAllowInsecure())
        throw new Exception("Informational node changed during export/reimport");
}
if (notices.Count == 2) Console.WriteLine("PASS: English and Chinese notices imported and retained with synthetic addresses");
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
