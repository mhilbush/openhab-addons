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
package org.openhab.binding.sunsetwx.internal;

import static org.openhab.binding.sunsetwx.internal.SunsetWxBindingConstants.*;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.openhab.binding.sunsetwx.internal.handler.SunsetWxAccountHandler;
import org.openhab.binding.sunsetwx.internal.handler.SunsetWxHandler;
import org.openhab.core.i18n.LocaleProvider;
import org.openhab.core.i18n.LocationProvider;
import org.openhab.core.io.net.http.HttpClientFactory;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingTypeUID;
import org.openhab.core.thing.binding.BaseThingHandlerFactory;
import org.openhab.core.thing.binding.ThingHandler;
import org.openhab.core.thing.binding.ThingHandlerFactory;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * The {@link SunsetWxHandlerFactory} is responsible for creating things and thing
 * handlers.
 *
 * @author Mark Hilbush - Initial contribution
 */
@NonNullByDefault
@Component(service = ThingHandlerFactory.class, configurationPid = "binding.sunsetwx")
public class SunsetWxHandlerFactory extends BaseThingHandlerFactory {

    private final HttpClient httpClient;
    private final LocationProvider locationProvider;
    private final LocaleProvider localeProvider;

    @Activate
    public SunsetWxHandlerFactory(@Reference HttpClientFactory httpClientFactory,
            @Reference LocationProvider locationProvider, @Reference LocaleProvider localeProvider) {
        this.httpClient = httpClientFactory.getCommonHttpClient();
        this.locationProvider = locationProvider;
        this.localeProvider = localeProvider;
    }

    @Override
    public boolean supportsThingType(ThingTypeUID thingTypeUID) {
        return SUPPORTED_THING_TYPES_UIDS.contains(thingTypeUID);
    }

    @Override
    protected @Nullable ThingHandler createHandler(Thing thing) {
        ThingTypeUID thingTypeUID = thing.getThingTypeUID();
        if (SUPPORTED_BRIDGE_THING_TYPES_UIDS.contains(thingTypeUID)) {
            return new SunsetWxAccountHandler((Bridge) thing, httpClient, locationProvider, localeProvider);
        } else if (SUPPORTED_SUNSETWX_THING_TYPES_UIDS.contains(thingTypeUID)) {
            return new SunsetWxHandler(thing);
        }
        return null;
    }
}
