package org.hum.wiretiger.proxy.facade.lite;

import org.hum.wiretiger.proxy.facade.enumtype.WiretigerPipeStatus;
import org.hum.wiretiger.proxy.pipe.enumtype.Protocol;

import lombok.Data;

@Data
public class WiretigerFullPipe {

	private String pipeId;
	private String sourceHost;
	private Integer sourcePort;
	private String targetHost;
	private Integer targetPort;
	private Protocol protocol;
	private WiretigerPipeStatus status;
}
