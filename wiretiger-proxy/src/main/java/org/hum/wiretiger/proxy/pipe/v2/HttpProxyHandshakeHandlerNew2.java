package org.hum.wiretiger.proxy.pipe.v2;

import org.hum.wiretiger.common.constant.HttpConstant;
import org.hum.wiretiger.proxy.pipe.WtPipeManager;
import org.hum.wiretiger.proxy.pipe.bean.WtPipeHolder;
import org.hum.wiretiger.proxy.pipe.constant.Constant;
import org.hum.wiretiger.proxy.pipe.enumtype.Protocol;
import org.hum.wiretiger.proxy.pipe.event.EventHandler;
import org.hum.wiretiger.ssl.HttpSslContextFactory;

import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Sharable
public class HttpProxyHandshakeHandlerNew2 extends SimpleChannelInboundHandler<HttpRequest> {
	
	private EventHandler eventHandler;
	
	public HttpProxyHandshakeHandlerNew2(EventHandler eventHandler) {
		this.eventHandler = eventHandler;
	}
	
    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        // 在第一时间初始化Pipe
        WtPipeHolder pipeHolder = WtPipeManager.get().create(ctx.channel());
        ctx.channel().attr(AttributeKey.valueOf(Constant.ATTR_PIPE)).set(pipeHolder);
        eventHandler.fireConnectEvent(pipeHolder);
        ctx.fireChannelActive();
    }

	@Override
	protected void channelRead0(ChannelHandlerContext client2ProxyCtx, HttpRequest request) throws Exception {
		
		// read host and port from http-request
		String[] hostAndPort = request.headers().get(HttpConstant.Host).split(":");
		String host = hostAndPort[0];
		int port = guessPort(request.method().name(), hostAndPort);
		
		// wrap pipeholder
		WtPipeHolder pipeHolder = (WtPipeHolder) client2ProxyCtx.channel().attr(AttributeKey.valueOf(Constant.ATTR_PIPE)).get();
		
    	if (HttpConstant.HTTPS_HANDSHAKE_METHOD.equalsIgnoreCase(request.method().name())) {
    		pipeHolder.setProtocol(Protocol.HTTPS);
    		log.info("HTTPS connect");
    		// 建立完成Pipe
    		FullPipe full = new FullPipe(new FrontPipe(client2ProxyCtx.channel()), new BackPipe(host, port, true), eventHandler, pipeHolder);
    		// SSL部分：根据域名颁发证书
    		SslHandler sslHandler = new SslHandler(HttpSslContextFactory.createSSLEngine(host));
			sslHandler.handshakeFuture().addListener(new GenericFutureListener<Future<? super Channel>>() {
				@Override
				public void operationComplete(Future<? super Channel> future) throws Exception {
					if (!future.isSuccess()) {
						log.error("{}, handshake failed", hostAndPort, future.cause());
						return ;
					}
		    		client2ProxyCtx.pipeline().addLast(new HttpServerCodec());
		    		client2ProxyCtx.pipeline().addLast(full);
				}
			});
			client2ProxyCtx.pipeline().addLast(sslHandler);
			
			// 在TLS握手前，先不要掺杂HTTP编解码器，等TLS握手完成后，统一添加HTTP编解码部分
			client2ProxyCtx.pipeline().remove(HttpRequestDecoder.class);
			client2ProxyCtx.pipeline().remove(HttpResponseEncoder.class);
			client2ProxyCtx.pipeline().remove(this);
			
			// 打通全链路后，给客户端发送200完成请求，告知可以发送业务数据
			full.connect().addListener(f -> {
				client2ProxyCtx.pipeline().firstContext().writeAndFlush(Unpooled.wrappedBuffer(HttpConstant.ConnectedLine.getBytes()));
			});
    	} else {
    		log.info("HTTP connect");
    		pipeHolder.setProtocol(Protocol.HTTP);
    		BackPipe back = new BackPipe(host, port, false);
    		FullPipe full = new FullPipe(new FrontPipe(client2ProxyCtx.channel()), back, eventHandler, pipeHolder);
    		full.connect().addListener(f-> {
    			back.getChannel().writeAndFlush(request);
    		});
    	}
	}
	
	private int guessPort(String method, String[] hostAndPort) {
		if (hostAndPort.length == 2) {
			return Integer.parseInt(hostAndPort[1]);
		} else if (HttpConstant.HTTPS_HANDSHAKE_METHOD.equalsIgnoreCase(method)) {
			return HttpConstant.DEFAULT_HTTPS_PORT;
		} else {
			return HttpConstant.DEFAULT_HTTP_PORT;
		}
	}
}
