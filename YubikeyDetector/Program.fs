module YubikeyDetector

open System
open System.Diagnostics
open System.Management
open Microsoft.Win32
open System.Collections.Generic

let yubikeys = HashSet<string>()

let debugSession _ =
    use searcher = new ManagementObjectSearcher("select * from Win32_LogonSession")
    searcher.Get() |> Seq.cast<ManagementObject> |> Seq.iter (fun d -> printfn "LoginId=%A LogonType=%A Status=%A" d.["LogonId"] d.["LogonType"] d.["Status"])
    use searcher2 = new ManagementObjectSearcher("select * from Win32_LoggedOnUser")
    searcher2.Get() |> Seq.cast<ManagementObject> |> Seq.iter (fun d -> printfn "Antecedent=%A Dependent=%A" d.["Antecedent"] d.["Dependent"])

let lockSession _ =
    Process.Start("rundll32.exe", "user32.dll,LockWorkStation").WaitForExit()
    printfn "Session locked"
    debugSession ()

let searchYubiKeys _ =
    use searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE Caption LIKE '%yubico%'")
    searcher.Get() |> Seq.cast<ManagementObject> |> Seq.map (fun d -> d.["DeviceID"] |> string) |> Seq.toList

let onDeviceConnected _ =
    searchYubiKeys() |> Seq.iter (fun key -> if yubikeys.Add(key) then printfn "%s connected!" key)

let onDeviceDisconnected _ =
    yubikeys |> Seq.except (searchYubiKeys()) |> Seq.toList |> List.iter (fun key -> 
        yubikeys.Remove(key) |> ignore
        printfn "%s disconnected!" key)

    if yubikeys.Count = 0
    then lockSession()

let onEventRaised (evt: EventArrivedEventArgs) =
    match evt.NewEvent.Properties |> Seq.cast<PropertyData> |> Seq.find (fun p -> p.Name = "EventType") |> fun p -> p.Value.ToString() with
    | "2" -> onDeviceConnected()
    | "3" -> onDeviceDisconnected()
    | _ -> ()

[<EntryPoint>]
let main _ =
    use watcher = new ManagementEventWatcher()
    let query = new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent")
    use _subcribe = watcher.EventArrived.Subscribe(onEventRaised)
    watcher.Query <- query
    watcher.Start()

    onDeviceConnected ()
    debugSession ()

    Console.ReadLine() |> ignore

    0
