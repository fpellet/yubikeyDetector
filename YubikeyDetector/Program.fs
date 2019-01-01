module YubikeyDetector

open System

type Disposables(disposables: IDisposable list) =
    interface IDisposable with
        member __.Dispose() = 
            disposables |> List.iter (fun d -> d.Dispose())

module WmiUsbDevices =
    open System.Management

    let private listenEvents query (listener: EventArrivedEventArgs -> unit) =
        let watcher = new ManagementEventWatcher()
        let subscription = watcher.EventArrived.Subscribe(listener)
        watcher.Query <- new WqlEventQuery(query)
        watcher.Start()

        new Disposables([watcher; subscription])

    let private search (query: string) parser =
        use searcher = new ManagementObjectSearcher(query)
        searcher.Get() |> Seq.cast<ManagementObject> |> Seq.map parser |> Seq.toList

    type DeviceChanges =
        | NewDeviceConnected
        | DeviceDisconnected

    let private DeviceChangesParser (evt: EventArrivedEventArgs) =
        match evt.NewEvent.["EventType"] :?> uint16 with
        | 2us -> Some NewDeviceConnected
        | 3us -> Some DeviceDisconnected
        | _ -> None

    let listenDeviceChanges (listener: DeviceChanges -> unit) = 
        DeviceChangesParser >> Option.bind (listener >> Some) >> ignore
        |> listenEvents "SELECT * FROM Win32_DeviceChangeEvent"
        
    type YubikeyId = string

    let searchYubikeys () : YubikeyId list =
        search "SELECT * FROM Win32_PnPEntity WHERE Caption LIKE '%yubico%'" (fun device -> device.["DeviceID"] :?> string)

module Yubikeys =
    open WmiUsbDevices

    type Changes =
        | NewYubikeyConnected of YubikeyId
        | YubikeyDisconnected of YubikeyId

    let private knownConnectedKeys = System.Collections.Generic.HashSet<YubikeyId>()

    let private onKeyConnected listener key =
        knownConnectedKeys.Add key |> ignore
        NewYubikeyConnected key |> listener

    let private onKeyDisconnected listener key =
        knownConnectedKeys.Remove key |> ignore
        YubikeyDisconnected key |> listener

    let private onDeviceConnected listener =
        searchYubikeys () 
        |> Seq.filter (knownConnectedKeys.Contains >> not)
        |> Seq.iter (onKeyConnected listener)

    let private onDeviceDisconnected listener =
        knownConnectedKeys
        |> Seq.except (searchYubikeys ())
        |> Seq.toList
        |> Seq.iter (onKeyDisconnected listener)

    let private onEventRaised listener = function
        | NewDeviceConnected -> onDeviceConnected listener
        | DeviceDisconnected -> onDeviceDisconnected listener

    let private registerCurrentDevice = onDeviceConnected

    let watch listener = 
        let watcher = listenDeviceChanges (onEventRaised listener)
        registerCurrentDevice listener
        watcher

    let hasConnectedKey () =
        knownConnectedKeys.Count > 0

module Sessions =
    open System.Diagnostics
    open Microsoft.Win32

    let lock () =
        use command = Process.Start("rundll32.exe", "user32.dll,LockWorkStation")
        command.WaitForExit()
        
    let private onSessionSwitch onUnlock _ (evt: SessionSwitchEventArgs) =
        printfn "Session %A" evt.Reason

        match evt.Reason with
        | SessionSwitchReason.SessionLogon
        | SessionSwitchReason.SessionUnlock -> onUnlock ()
        | _ -> ()

    let watch onUnlock =
        SystemEvents.SessionSwitch.AddHandler(SessionSwitchEventHandler(onSessionSwitch onUnlock));
        

module Watcher =
    open Yubikeys

    let private lockSessionIfNoKey () =
        match hasConnectedKey () with
        | true -> ()
        | false ->
            Sessions.lock ()
            printfn "No key => Session locked"

    let private onKeyChanged = function
        | NewYubikeyConnected id ->
            printfn "%s connected" id

        | YubikeyDisconnected id ->
            printfn "%s disconnected" id
            lockSessionIfNoKey ()
        
    let run () =
        let keysWatcher = Yubikeys.watch onKeyChanged
        Sessions.watch lockSessionIfNoKey
        lockSessionIfNoKey ()
        keysWatcher

let succeedExitCode = 0
   
[<EntryPoint>]
let main _ =
    use _watcher = Watcher.run ()

    Console.ReadLine() |> ignore

    succeedExitCode
