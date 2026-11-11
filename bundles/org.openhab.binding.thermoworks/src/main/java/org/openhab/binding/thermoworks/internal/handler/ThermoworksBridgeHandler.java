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
package org.openhab.binding.thermoworks.internal.handler;

import static org.openhab.binding.thermoworks.internal.ThermoworksBindingConstants.*;

import java.math.BigDecimal;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.StreamSupport;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksDeviceDTO;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksResponseDTO;
import org.openhab.core.config.core.Configuration;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseBridgeHandler;
import org.openhab.core.types.Command;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

/**
 * ThermoworksBridgeHandler
 *
 * @author Mark Hilbush - Initial contribution
 */
@NonNullByDefault
public class ThermoworksBridgeHandler extends BaseBridgeHandler {

    private final Logger logger = LoggerFactory.getLogger(ThermoworksBridgeHandler.class);
    private final Gson gson = new Gson();

    // private static final String API_URL_ACCOUNT = "https://cloud.thermoworks.com/api/v1/me";
    private static final String API_URL_DEVICES = "https://cloud.thermoworks.com/api/v1/devices";
    private static final int HTTP_TIMEOUT_SECONDS = 10;

    private static final int ONLINE_POLL_CYCLES = 1;
    private static final int OFFLINE_POLL_CYCLES = 3;

    private @Nullable ScheduledFuture<?> pollingJob = null;
    private @Nullable String apiKey;
    private int refreshIntervalSeconds = 60;
    private int numPollCyclesToWait = 0;

    private final HttpClient httpClient;

    private @Nullable String eTag = null;

    public ThermoworksBridgeHandler(Bridge bridge, HttpClient httpClient) {
        super(bridge);
        this.httpClient = httpClient;
    }

    @Override
    public void initialize() {
        Configuration config = getConfig();

        Object intervalObj = config.get(CONFIG_REFRESH_INTERVAL_SECONDS);
        refreshIntervalSeconds = switch (intervalObj) {
            case BigDecimal seconds -> seconds.intValue();
            case Integer seconds -> seconds;
            case null, default -> 60;
        };
        if (refreshIntervalSeconds < 15) {
            logger.debug("BridgeHandler: Refresh interval of {} is too low, defaulting to 60", refreshIntervalSeconds);
            refreshIntervalSeconds = 60;
        }
        logger.debug("BridgeHandler: Binding will poll for new data every {} seconds", refreshIntervalSeconds);

        apiKey = (String) config.get(CONFIG_API_KEY);
        if (apiKey == null || (apiKey != null && apiKey.isEmpty())) {
            updateStatus(ThingStatusDetail.CONFIGURATION_ERROR, "Missing API Key");
            return;
        }

        startPolling();
        updateStatus(ThingStatus.ONLINE);
    }

    @Override
    public void dispose() {
        stopPolling();
        super.dispose();
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        logger.debug("BridgeHandler: Received command {} for channel {}", command, channelUID);
    }

    public @Nullable String fetchCloudData() {
        return fetchCloudData(true);
    }

    public @Nullable String fetchCloudData(boolean includeETag) {
        if (numPollCyclesToWait > 0) {
            logger.debug("Rate limit exceeded, waiting {} poll cycles", numPollCyclesToWait);
            numPollCyclesToWait--;
            return null;
        }
        try {
            logger.debug("BridgeHandler: Fetching data for all devices...");
            Request request = httpClient.newRequest(API_URL_DEVICES).method(HttpMethod.GET)
                    .header(HttpHeader.AUTHORIZATION, "Bearer " + apiKey).header(HttpHeader.ACCEPT, "application/json")
                    .timeout(HTTP_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (includeETag && eTag != null) {
                request.header("If-None-Match", eTag);
            }
            ContentResponse response = request.send();
            eTag = response.getHeaders().get("ETag");

            if (logger.isTraceEnabled()) {
                logger.debug("Dumping headers...");
                StreamSupport.stream(response.getHeaders().spliterator(), false)
                        .filter(header -> header.getName().startsWith("X-Rate"))
                        .forEach(header -> logger.debug("Response header: {}:{}", header.getName(), header.getValue()));
            }

            int statusCode = response.getStatus();
            if (statusCode == HttpStatus.OK_200) {
                updateStatus(ThingStatus.ONLINE);
                return response.getContentAsString();
            } else if (statusCode == HttpStatus.UNAUTHORIZED_401 || statusCode == HttpStatus.FORBIDDEN_403) {
                updateStatus(ThingStatusDetail.CONFIGURATION_ERROR,
                        "Invalid API Key or unauthorized access (HTTP " + statusCode + ")");
            } else if (statusCode == HttpStatus.TOO_MANY_REQUESTS_429) {
                logger.info("BridgeHandler: Rate limit reached (HTTP 429), wait Retry-After seconds before polling");
                String retryAfterStr = response.getHeaders().get("Retry-After");
                logger.debug("BridgeHandler: Retry poll after {} seconds", retryAfterStr);
                updateStatus(ThingStatusDetail.CONFIGURATION_ERROR,
                        "Poll rate exceeded, retry after " + retryAfterStr + " seconds");
                numPollCyclesToWait = calculatePollCyclesToWait(retryAfterStr);
            } else if (statusCode == HttpStatus.NOT_MODIFIED_304) {
                logger.debug("BridgeHandler: Data was not modified since last call (HTTP 304");
                updateStatus(ThingStatus.ONLINE);
            } else {
                logger.warn("BridgeHandler: ThermoWorks Cloud API returned unexpected status code: {}", statusCode);
                updateStatus(ThingStatus.OFFLINE, String.format("Unexpected HTTP status code received %d", statusCode));
            }
        } catch (InterruptedException | TimeoutException | ExecutionException e) {
            logger.info("BridgeHandler: Transport exception hitting ThermoWorks Cloud: {}", e.getMessage(), e);
            updateStatus(ThingStatusDetail.COMMUNICATION_ERROR, e.getMessage());
        }
        return null;
    }

    /*
     * Number of poll cycles to wait based on value returned in Retry-After header in HTTP 429 response
     */
    private int calculatePollCyclesToWait(@Nullable String retryAfterStr) {
        int pollCycles = 0;
        if (retryAfterStr != null && !retryAfterStr.isEmpty()) {
            try {
                int retryAfterSeconds = Integer.parseInt(retryAfterStr);
                pollCycles = retryAfterSeconds / refreshIntervalSeconds;
            } catch (NumberFormatException e) {
                // If we can't parse it, don't wait
            }
        }
        return pollCycles;
    }

    public Gson getGson() {
        return gson;
    }

    private synchronized void startPolling() {
        stopPolling();
        pollingJob = scheduler.scheduleWithFixedDelay(this::pollDeviceStatus, 4, refreshIntervalSeconds,
                TimeUnit.SECONDS);
    }

    private synchronized void stopPolling() {
        ScheduledFuture<?> localPollingJob = pollingJob;
        if (localPollingJob != null && !localPollingJob.isCancelled()) {
            localPollingJob.cancel(true);
            pollingJob = null;
        }
    }

    private void pollDeviceStatus() {
        logger.debug("BridgeHandler: Polling ThermoWorks Cloud API for device status...");
        String devices = fetchCloudData();
        if (devices != null) {
            if (logger.isTraceEnabled()) {
                logger.trace("BridgeHandler: Received device data: {}", devices);
            }
            handlePayload(devices);
        }
    }

    private void handlePayload(@Nullable String jsonResponseBody) {
        logger.debug("BridgeHandler: Handling payload received from cloud API");
        ThermoworksResponseDTO response;
        try {
            response = gson.fromJson(jsonResponseBody, ThermoworksResponseDTO.class);
        } catch (JsonSyntaxException e) {
            logger.debug("BridgeHandler: Exception parsing JSON response from Cloud API: {}", e.getMessage(), e);
            return;
        }
        if (response == null || response.getDevices() == null) {
            logger.info("BridgeHandler: Payload is null or contains no devices");
            return;
        }

        for (ThermoworksDeviceDTO device : response.getDevices()) {
            if (device == null) {
                continue;
            }
            String serialNumber = device.getSerialNumber();
            if (serialNumber == null || serialNumber.isEmpty()) {
                logger.warn("BridgeHandler: Device serial number is null or empty, cannot update device state");
                continue;
            }
            String model = device.getModel() != null ? device.getModel().toUpperCase() : "";
            logger.debug("BridgeHandler: Handling device update for model <{}> with serial number {}", model,
                    serialNumber);

            ThermoworksDeviceHandler handler = getDeviceHandler(serialNumber);
            if (handler != null) {
                logger.debug("BridgeHandler: Sending payload to thing handler for serial number {}", serialNumber);
                determineOnlineStatus(serialNumber, device);
                handler.handlePayloadUpdate(device);
            }
        }
    }

    private void determineOnlineStatus(String serialNumber, ThermoworksDeviceDTO device) {
        /*
         * The API doesn't provide an online/offline status indicator,
         * so we determine it based on the lastUpdated timestamp
         * If lastUpdated is not changed in the last OFFLINE_POLL_CYCLES or more poll cycles, set device to offline
         * If lastUpdated is within last ONLINE_POLL_CYCLES or less poll cycles, set to online
         */
        String lastUpdated = device.getLastUpdated();
        if (lastUpdated == null) {
            device.setIsOnline(Boolean.FALSE);
            return;
        }

        ZonedDateTime zdtLastUpdated;
        try {
            zdtLastUpdated = ZonedDateTime.parse(lastUpdated);
        } catch (DateTimeParseException e) {
            logger.info("BridgeHandler: Invalid lastUpdated timestamp for device {}: {}", serialNumber,
                    device.getLastUpdated());
            device.setIsOnline(Boolean.FALSE);
            return;
        }
        ZonedDateTime zdtNow = ZonedDateTime.now();
        long secondsSinceLastUpdate = java.time.Duration.between(zdtLastUpdated, zdtNow).getSeconds();
        long secondsPerPollCycle = refreshIntervalSeconds;
        long pollCyclesSinceLastUpdate = secondsSinceLastUpdate / secondsPerPollCycle;
        if (pollCyclesSinceLastUpdate >= OFFLINE_POLL_CYCLES) {
            logger.debug("BridgeHandler: Device {} is OFFLINE (last updated {} seconds ago [{} poll cycles]",
                    serialNumber, secondsSinceLastUpdate, pollCyclesSinceLastUpdate);
            device.setIsOnline(Boolean.FALSE);
        } else if (pollCyclesSinceLastUpdate <= ONLINE_POLL_CYCLES) {
            logger.debug("BridgeHandler: Device {} is ONLINE (last updated {} seconds ago [{} poll cycles]",
                    serialNumber, secondsSinceLastUpdate, pollCyclesSinceLastUpdate);
            device.setIsOnline(Boolean.TRUE);
        } else {
            logger.debug("BridgeHandler: Device {} status is UNKNOWN (last updated {} seconds ago [{} poll cycles])",
                    serialNumber, secondsSinceLastUpdate, pollCyclesSinceLastUpdate);
            device.setIsOnline(Boolean.FALSE);
        }
    }

    private @Nullable ThermoworksDeviceHandler getDeviceHandler(String serialNumber) {
        for (Thing thing : getThing().getThings()) {
            if (serialNumber.equals(thing.getConfiguration().get(CONFIG_SERIALNUMBER))
                    && thing.getHandler() instanceof ThermoworksDeviceHandler) {
                logger.debug("BridgeHandler: Found device handler for serialNumber: {}", serialNumber);
                return (ThermoworksDeviceHandler) thing.getHandler();
            }
        }
        return null;
    }
}
