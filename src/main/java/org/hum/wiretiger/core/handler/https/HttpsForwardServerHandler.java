package org.hum.wiretiger.core.handler.https;

import org.hum.wiretiger.core.external.conmonitor.ConnectionStatus;
import org.hum.wiretiger.core.handler.bean.Pipe;
import org.hum.wiretiger.core.handler.helper.HttpsClient;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

public class HttpsForwardServerHandler extends SimpleChannelInboundHandler<HttpObject> {

	private String host;
	private int port;

	public HttpsForwardServerHandler(String host, int port) {
		this.host = host;
		this.port = port;
	}

	@Override
	public void channelReadComplete(ChannelHandlerContext ctx) {
		ctx.flush();
	}

	@Override
	public void channelRead0(ChannelHandlerContext ctx, HttpObject msg) throws Exception {

		if (msg instanceof DefaultHttpRequest) {
			((Pipe) ctx.channel().attr(AttributeKey.valueOf(Pipe.PIPE_ATTR_NAME)).get()).setStatus(ConnectionStatus.Forward);
			((Pipe) ctx.channel().attr(AttributeKey.valueOf(Pipe.PIPE_ATTR_NAME)).get()).setRequest((DefaultHttpRequest) msg);
			FullHttpResponse response = HttpsClient.send(host, port, (HttpRequest) msg);
			ctx.writeAndFlush(response).addListener(new GenericFutureListener<Future<? super Void>>() {
				@Override
				public void operationComplete(Future<? super Void> future) throws Exception {
					((Pipe) ctx.channel().attr(AttributeKey.valueOf(Pipe.PIPE_ATTR_NAME)).get()).setStatus(ConnectionStatus.Read);
				}
			});
		}
	}

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
		cause.printStackTrace();
		ctx.close();
	}
}