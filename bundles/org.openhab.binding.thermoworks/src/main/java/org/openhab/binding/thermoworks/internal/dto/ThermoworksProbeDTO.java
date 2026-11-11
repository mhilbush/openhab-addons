/*
 * Copyright (c) 2010-2026 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.thermoworks.internal.dto;

import com.google.gson.annotations.SerializedName;

/**
 *
 * ThermoworksProbeDTO
 *
 * @author Mark Hilbush - Initial contribution
 */
public class ThermoworksProbeDTO {

    @SerializedName(value = "number", alternate = { "id" })
    private Integer probeId;

    @SerializedName("label")
    private String label;

    @SerializedName("type")
    private String type;

    @SerializedName(value = "value", alternate = { "temp" })
    private Double currentTemperature;

    @SerializedName(value = "units", alternate = { "unit" })
    private String temperatureUnit;

    @SerializedName("status")
    private String status;

    @SerializedName("alarmHigh")
    private AlarmLimit alarmHigh;

    @SerializedName("alarmLow")
    private AlarmLimit alarmLow;

    @SerializedName("alarming")
    private Boolean isAlarmTriggered;

    public static class AlarmLimit {
        @SerializedName("enabled")
        private Boolean enabled;

        @SerializedName("value")
        private Integer temperature;

        @SerializedName("alarming")
        private Boolean alarming;

        public Boolean getEnabled() {
            return enabled;
        }

        public Integer getValue() {
            return temperature;
        }

        public Boolean getAlarming() {
            return alarming;
        }
    }

    public Integer getProbeId() {
        return probeId;
    }

    public void setProbeId(Integer probeId) {
        this.probeId = probeId;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Double getCurrentTemperature() {
        return roundToTenth(currentTemperature);
    }

    public void setCurrentTemperature(Double currentTemperature) {
        this.currentTemperature = roundToTenth(currentTemperature);
    }

    public String getTemperatureUnit() {
        return temperatureUnit;
    }

    public void setTemperatureUnit(String temperatureUnit) {
        this.temperatureUnit = temperatureUnit;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Boolean getIsAlarmTriggered() {
        return isAlarmTriggered != null ? isAlarmTriggered : Boolean.FALSE;
    }

    public Boolean getIsAlarmHighEnabled() {
        Boolean alarmEnabled = alarmHigh != null ? alarmHigh.getEnabled() : false;
        return alarmEnabled != null ? alarmEnabled : false;
    }

    public Integer getAlarmHighTemperature() {
        return alarmHigh != null ? alarmHigh.getValue() : null;
    }

    public Boolean getIsAlarmHighTriggered() {
        Boolean getAlarming = alarmHigh != null ? alarmHigh.getAlarming() : false;
        return getAlarming != null ? getAlarming : false;
    }

    public Boolean getIsAlarmLowEnabled() {
        Boolean alarmEnabled = alarmLow != null ? alarmLow.getEnabled() : false;
        return alarmEnabled != null ? alarmEnabled : false;
    }

    public Integer getAlarmLowTemperature() {
        return alarmLow != null ? alarmLow.getValue() : null;
    }

    public Boolean getIsAlarmLowTriggered() {
        Boolean getAlarming = alarmLow != null ? alarmLow.getAlarming() : false;
        return getAlarming != null ? getAlarming : false;
    }

    private double roundToTenth(double value) {
        return Math.round(value * 10.0) / 10.0;
    }
}
