# ThermoWorks Binding

This binding integrates ThermoWorks WiFi-enabled thermometers (such as RFX Gateway/Meat, Signals and Smoke via Thermoworks cloud) into openHAB.

## Supported Things

This binding supports a Thermoworks cloud account bridge and individual ThermoWorks devices with multi-probe capabilities.
A generic thing type is provided for devices that might be discovered but are not yet supported by the binding.
Generic devices will have very limited functionality (i.e. one temperature probe that may or may not work).

| Thing Type               | ID           | Description                                                                            |
|--------------------------|--------------|----------------------------------------------------------------------------------------|
| ThermoWorks Account      | account      | Bridge thing handling authentication and communication with the ThermoWorks Cloud API  |
| ThermoWorks RFX Gateway  | rfx-gateway  | A ThermoWorks RFX Wireless Gateway                                                     |
| ThermoWorks RFX Meat     | rfx-meat     | A Thermoworks RFX Wireless Meat probe                                                  |
| ThermoWorks Signals      | signals      | A ThermoWorks Signals device with 4 temperature probes                                 |
| ThermoWorks Smoke        | smoke        | A ThermoWorks Smoke device with 2 temperature probes                                   |
| ThermoWorks Generic      | generic      | The thing type assigned when the model is not recognized/supported by the binding      |

## Discovery

Once the **ThermoWorks Account** bridge is created and configured with a valid apiKey, you can manually run a discovery scan to
find the ThermoWorks devices in your Thermoworks cloud account that are registered to the API key.

## Thing Configuration

### ThermoWorks Account

The account bridge requires your ThermoWorks cloud api key and a polling interval.
The apiKey is created in your Thermoworks Cloud account at cloud.thermoworks.com.
You can assign one, more than one, or all of your devices to an API key.
Configuring a fast polling interval may result in rate limiting / throttling of cloud API requests.

| Parameter              | Type    | Required   | Default | Description                                             |
|------------------------|---------|------------|---------|---------------------------------------------------------|
| apiKey                 | Text    | Yes        |  none   | apiKey created in your ThermoWorks cloud account        |
| refreshIntervalSeconds | Integer | Yes        |    60   | Data polling interval in seconds (minimum 15 seconds)   |

### ThermoWorks Devices

Devices are typically discovered automatically, but also can be added manually.

| Parameter      | Type | Required | Description                                                                       |
|----------------|------|----------|-----------------------------------------------------------------------------------|
| serialNumber   | Text | Yes      | Unique ThermoWorks device identifier (found in the cloud app or inbox discovery)  |

## Channels

### ThermoWorks Devices

ThermoWorks devices provide channels for device online state, battery level, WiFi signal strength, and channels for up to 4 probes,
depending on the device model.
All channels are readonly as the Thermoworks cloud API does not support updates.
Temperature channels will report UNDEF when the device is offline.

| Channel                        | Item Type                | Description                                          |
|--------------------------------|--------------------------|------------------------------------------------------|
| online                         | Switch                   | Online status of the physical device (ON / OFF)      |
| ambient-temperature            | Number:Temperature       | Ambient temperature probe (RFX Gateway only)         |
| battery-level                  | Number:Dimensionless     | Remaining battery percentage (0–100%)                |
| battery-state                  | String                   | Battery is charging or discharging                   |
| rssi                           | Number:Power             | Wi-Fi / Bluetooth RSSI signal strength (dBm)         |
|                                |                          |                                                      |
| probe1-temperature             | Number:Temperature       | Current temperature reading for probe                |
| probe1-label                   | String                   | Label assigned to the probe                          |
| probe1-alarm                   | Switch                   | Active alarm indicator for probe (ON / OFF)          |
| probe1-alarm-high-enabled      | Switch                   | High temperature alarm enabled                       |
| probe1-alarm-high-temperature  | Number:Temperature       | Temperature at which to alarm                        |
| probe1-alarm-high-alarm        | Switch                   | Indicates if high temperature alarm is triggered     |
| probe1-alarm-low-enabled       | Switch                   | Low temperature alarm enabled                        |
| probe1-alarm-low-temperature   | Number:Temperature       | Temperature at which to alarm                        |
| probe1-alarm-low-alarm         | Switch                   | Indicates if low temperature alarm is triggered      |
|                                |                          |                                                      |
| probe2-temperature             | Number:Temperature       | Current temperature reading for probe                |
| probe2-label                   | String                   | Label assigned to the probe                          |
| probe2-alarm                   | Switch                   | Active alarm indicator for probe (ON / OFF)          |
| probe2-alarm-high-enabled      | Switch                   | High temperature alarm enabled                       |
| probe2-alarm-high-temperature  | Number:Temperature       | Temperature at which to alarm                        |
| probe2-alarm-high-alarm        | Switch                   | Indicates if high temperature alarm is triggered     |
| probe2-alarm-low-enabled       | Switch                   | Low temperature alarm enabled                        |
| probe2-alarm-low-temperature   | Number:Temperature       | Temperature at which to alarm                        |
| probe2-alarm-low-alarm         | Switch                   | Indicates if low temperature alarm is triggered      |
|                                |                          |                                                      |
| probe3-temperature             | Number:Temperature       | Current temperature reading for probe                |
| probe3-label                   | String                   | Label assigned to the probe                          |
| probe3-alarm                   | Switch                   | Active alarm indicator for probe (ON / OFF)          |
| probe3-alarm-high-enabled      | Switch                   | High temperature alarm enabled                       |
| probe3-alarm-high-temperature  | Number:Temperature       | Temperature at which to alarm                        |
| probe3-alarm-high-alarm        | Switch                   | Indicates if high temperature alarm is triggered     |
| probe3-alarm-low-enabled       | Switch                   | Low temperature alarm enabled                        |
| probe3-alarm-low-temperature   | Number:Temperature       | Temperature at which to alarm                        |
| probe3-alarm-low-alarm         | Switch                   | Indicates if low temperature alarm is triggered      |
|                                |                          |                                                      |
| probe4-temperature             | Number:Temperature       | Current temperature reading for probe                |
| probe4-label                   | String                   | Label assigned to the probe                          |
| probe4-alarm                   | Switch                   | Active alarm indicator for probe (ON / OFF)          |
| probe4-alarm-high-enabled      | Switch                   | High temperature alarm enabled                       |
| probe4-alarm-high-temperature  | Number:Temperature       | Temperature at which to alarm                        |
| probe4-alarm-high-alarm        | Switch                   | Indicates if high temperature alarm is triggered     |
| probe4-alarm-low-enabled       | Switch                   | Low temperature alarm enabled                        |
| probe4-alarm-low-temperature   | Number:Temperature       | Temperature at which to alarm                        |
| probe4-alarm-low-alarm         | Switch                   | Indicates if low temperature alarm is triggered      |

## Full Example

### `thermoworks.things`

```openhab
Bridge thermoworks:account:account "ThermoWorks Account" [ apiKey="sdkswjhdxkjwnecoiweoiwq", refreshIntervalSeconds=60 ] {
    Thing device signals "BBQ (Signals)" [ serialNumber="30c922b8db40" ]
}
```

### `thermoworks.items`

```openhab
// Device Channels
Number:Dimensionless  Signals_BatteryLevel        "Signals Battery Level [%d]"     <battery>     {channel="thermoworks:signals:account:30c922b8db40:battery"}
Number:Dimensionless  Signals_RSSI                "Signals Signal [%d]"                          {channel="thermoworks:signals:account:30c922b8db40:rssi"}
Switch                Signals_Online              "Signals Online [%s]"                          {channel="thermoworks:signals:account:30c922b8db40:online"}

// Probe 1 Channels
Number:Temperature    Signals_Probe1_Temperature  "Probe 1 Temperature [%.1f °F]"  <temperature>  {channel="thermoworks:signals:account:30c922b8db40:probe1-temperature"}
Switch                Signals_Probe1_Alarm        "Probe 1 Alarm [%s]"             <alarm>        {channel="thermoworks:signals:account:30c922b8db40:probe1-alarm"}
String                Signals_Probe1_Label        "Probe 1 Label [%s]"             <text>         {channel="thermoworks:signals:account:30c922b8db40:probe1-label"}

// Probe 2 Channels
Number:Temperature    Signals_Probe2_Temp         "Probe 2 Temperature [%.1f °F]"  <temperature>  {channel="thermoworks:signals:account:30c922b8db40:probe2-temperature"}
Switch                Signals_Probe2_Alarm        "Probe 2 Alarm [%s]"             <alarm>        {channel="thermoworks:signals:account:30c922b8db40:probe2-alarm"}
String                Signals_Probe2_Label        "Probe 2 Label [%s]"             <text>         {channel="thermoworks:signals:account:30c922b8db40:probe2-label"}
```

### `thermoworks.sitemap`

```openhab
sitemap thermoworks label="ThermoWorks Monitoring" {
    Frame label="BBQ smoke Status" {
        Text item=Signals_Online
        Text item=Signals_BatteryLevel
        Text item=Signals_RSSI
    }

    Frame label="Probe 1" {
        Text item=Signals_Probe1_Temperature
        Text item=Signals_Probe1_Alarm
        Text item=Signals_Probe1_Label
    }

    Frame label="Probe 2 - Brisket" {
        Text item=Signals_Probe2_Temperature
        Text item=Signals_Probe2_Alarm
        Text item=Signals_Probe2_Label
    }
}
```
