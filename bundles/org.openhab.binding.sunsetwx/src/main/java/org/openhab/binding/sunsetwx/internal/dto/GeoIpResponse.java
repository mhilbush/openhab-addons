/**
 * Copyright (c) 2010-2024 Contributors to the openHAB project
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
package org.openhab.binding.sunsetwx.internal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * The {@link GeoIpResponse} class is used to parse the response from the
 * location discovery API call.
 *
 * @author Mark Hilbush - Initial contribution
 */
public class GeoIpResponse {

    @SerializedName("lat")
    public Double lat;

    @SerializedName("lon")
    public Double lon;
}
