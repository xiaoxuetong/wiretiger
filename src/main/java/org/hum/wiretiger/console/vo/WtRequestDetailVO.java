package org.hum.wiretiger.console.vo;

import java.io.Serializable;

import lombok.Data;

@Data
public class WtRequestDetailVO implements Serializable {

	private static final long serialVersionUID = 1L;

	private String request;
	private String response;
	private String responseBytes;
}