package org.hum.wiretiger.proxy.server;

import java.util.ArrayList;
import java.util.List;

import org.hum.wiretiger.proxy.config.WtCoreConfig;
import org.hum.wiretiger.proxy.facade.event.EventListener;

public class WtServerBuilder {
	
	private WtCoreConfig config;
	
	private List<EventListener> listeners;

	public static WtServerBuilder init(WtCoreConfig config) {
		WtServerBuilder serverBuilder = new WtServerBuilder();
		serverBuilder.config = config;
		serverBuilder.listeners = new ArrayList<>();
		return serverBuilder;
	}
	
	private WtServerBuilder() {
	}
	
	public WtServerBuilder addEventListener(EventListener listener) {
		this.listeners.add(listener);
		return this;
	}

	public WtServer build() {
		WtDefaultServer server = new WtDefaultServer(config);
		server.setListeners(listeners);
		return server;
	}
}
