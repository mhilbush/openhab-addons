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

/**
 *
 * ThermoworksErrorDTO
 *
 * @author Mark Hilbush - Initial contribution
 */
public class ThermoworksErrorDTO {

    public ErrorDetailDto error;

    public ThermoworksErrorDTO(ErrorDetailDto error) {
        this.error = error;
    }

    public ErrorDetailDto getError() {
        return error;
    }

    public void setError(ErrorDetailDto error) {
        this.error = error;
    }

    public class ErrorDetailDto {
        private String code;
        private String message;

        public ErrorDetailDto() {
        }

        public ErrorDetailDto(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }
}
