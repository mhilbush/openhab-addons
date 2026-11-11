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

import java.util.List;

import com.google.gson.annotations.SerializedName;

/**
 *
 * ThermoworksAccountDTO
 *
 * @author Mark Hilbush - Initial contribution
 */
public class ThermoworksAccountDTO {

    @SerializedName("accountId")
    private String accountId;

    @SerializedName("apiKey")
    private ApiKeyDetails apiKey;

    @SerializedName("plan")
    private PlanDetails plan;

    @SerializedName("rateLimit")
    private RateLimitDetails rateLimit;

    @SerializedName("recommendedPollSeconds")
    private Integer recommendedPollSeconds;

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    public ApiKeyDetails getApiKey() {
        return apiKey;
    }

    public void setApiKey(ApiKeyDetails apiKey) {
        this.apiKey = apiKey;
    }

    public PlanDetails getPlan() {
        return plan;
    }

    public void setPlan(PlanDetails plan) {
        this.plan = plan;
    }

    public RateLimitDetails getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(RateLimitDetails rateLimit) {
        this.rateLimit = rateLimit;
    }

    public Integer getRecommendedPollSeconds() {
        return recommendedPollSeconds;
    }

    public void setRecommendedPollSeconds(Integer recommendedPollSeconds) {
        this.recommendedPollSeconds = recommendedPollSeconds;
    }

    // --- Inner Classes ---

    public static class ApiKeyDetails {

        @SerializedName("id")
        private String id;

        @SerializedName("name")
        private String name;

        @SerializedName("scopes")
        private List<String> scopes;

        @SerializedName("deviceIds")
        private List<String> deviceIds;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        public List<String> getDeviceIds() {
            return deviceIds;
        }

        public void setDeviceIds(List<String> deviceIds) {
            this.deviceIds = deviceIds;
        }
    }

    public static class PlanDetails {

        @SerializedName("id")
        private String id;

        @SerializedName("apiTier")
        private String apiTier;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getApiTier() {
            return apiTier;
        }

        public void setApiTier(String apiTier) {
            this.apiTier = apiTier;
        }
    }

    public static class RateLimitDetails {

        @SerializedName("perMinute")
        private Integer perMinute;

        @SerializedName("perDay")
        private Integer perDay;

        public Integer getPerMinute() {
            return perMinute;
        }

        public void setPerMinute(Integer perMinute) {
            this.perMinute = perMinute;
        }

        public Integer getPerDay() {
            return perDay;
        }

        public void setPerDay(Integer perDay) {
            this.perDay = perDay;
        }
    }
}
