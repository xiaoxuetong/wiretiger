package org.hum.wiretiger.console.vo;

import java.io.Serializable;

import lombok.Data;

@Data
public class RequestVO implements Serializable {

	private static final long serialVersionUID = 1L;
	
	// id
	private Integer reqeustId;
	// uri
	private String uri;
}