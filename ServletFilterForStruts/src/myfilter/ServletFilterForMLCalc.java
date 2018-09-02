package myfilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.util.*;
import java.util.regex.Pattern;

public class ServletFilterForMLCalc implements javax.servlet.Filter {
	private static final String ERROR_INVALID_REQUEST = "BlockedByServletFilterForOGNL.Please press back button.";
	private static final String filterName = "ServletFilterForOGNL";
	private static final String ML_URL = "http://10.1.0.100:5000/preds?str=";
	private static final int ML_RESULT_NORMAL = 201;
	private static final int ML_RESULT_ATTACK = 202;
	private static final String SIGNATURE_OGNL = 
			"OgnlContext|OgnlUtil|#context|@DEFAULT_MEMBER_ACCESS|#_memberAccess|java.lang.ProcessBuilder|java.lang.Runtime|%23context|%40DEFAULT_MEMBER_ACCESS|%23_memberAccess|java%2elang%2eProcessBuilder|java%2elang%2eRuntime";
	private Pattern p = Pattern.compile(SIGNATURE_OGNL);
	private FilterConfig filterConfig;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws java.io.IOException,
			javax.servlet.ServletException {
		String result="";
		String str="";

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		// URL
		String uri = httpRequest.getRequestURI();
		str+=uri;

		// Query
		String query = httpRequest.getQueryString();
		str+=query;

		// body
		String body = "";
		httpRequest.setCharacterEncoding("UTF-8");
		Enumeration names = httpRequest.getParameterNames();
		while (names.hasMoreElements()) {
			String name = (String) names.nextElement();
			String vals[] = request.getParameterValues(name);
			if (vals != null) {
				for (String s : vals) {
					body += s+"/";
				}
			}
		}
		str+=body;

		try {
			// header
			Enumeration<String> headernames = httpRequest.getHeaderNames();
			while (headernames.hasMoreElements()) {
				String name = (String) headernames.nextElement();
				Enumeration<String> headervals = httpRequest.getHeaders(name);
				while (headervals.hasMoreElements()) {
					String value = (String) headervals.nextElement();
					str+=value;
					//String decodedValue=URLDecoder.decode(value,"UTF-8");
					int resultML = getMLResult(value);
					if (ML_RESULT_ATTACK == resultML) {
						System.out.println(filterName + ":Malicious header:"
								+ name + ": " + value);
						throw new Exception(ERROR_INVALID_REQUEST);
					}
				}
			}

			int resultML;
			String decodedURI=URLDecoder.decode(uri,"UTF-8");
			if (null == query && null == body) {
				resultML = getMLResult(decodedURI);
				if (ML_RESULT_ATTACK == resultML) {
					System.out.println(filterName + ":Malicious URI:"
							+ uri);
					throw new Exception(ERROR_INVALID_REQUEST);
				}
			} else {
				if (null != query) {
					String decodedQuery=URLDecoder.decode(query,"UTF-8");
					resultML = getMLResult(decodedURI + "?" + decodedQuery);
					if (ML_RESULT_ATTACK == resultML) {
						System.out.println(filterName + ":Malicious query:"
								+ query);
						throw new Exception(ERROR_INVALID_REQUEST);
					}
				}
				if (null != body) {
					String decodedBody=URLDecoder.decode(body,"UTF-8");
					resultML = getMLResult(decodedURI + "?" + decodedBody);
					if (ML_RESULT_ATTACK == resultML) {
						System.out.println(filterName + ":Malicious body:"
								+ body);
						throw new Exception(ERROR_INVALID_REQUEST);
					}
				}
			}
		} catch (Exception se) {
			if(p.matcher(str).find()){
				// TP
				result="TP";
			} else{
				//FP
				result="FP";
			}
			System.out.println("result:"+result);
			System.out.println("str:"+str);
			throw new ServletException(se.getMessage());
		}
		// normal request
		if(p.matcher(str).find()){
			// FN
			result="FN";
			System.out.println("fnstr:"+str);
		} else{
			// TN
			result="TN";
		}
		System.out.println("result:"+result);
		chain.doFilter(request, response);
	}

	private int getMLResult(String targetStr) {
		//System.out.println("before encode targetStr: " + targetStr);
		URL url = null;
		int resCode = 0;
		try {
			try {
				String encodeStr = URLEncoder.encode(targetStr, "UTF-8");
				//System.out.println("after encodeStr: " + encodeStr);
				url = new URL(ML_URL + encodeStr);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		HttpURLConnection urlconn;
		try {
			urlconn = (HttpURLConnection) url.openConnection();
			urlconn.setRequestMethod("GET");
			urlconn.connect();
			resCode = urlconn.getResponseCode();
			System.out.println("resCode: " + resCode);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return resCode;

	}

	@Override
	public void init(final FilterConfig filterConfig) {
		this.filterConfig = filterConfig;
	}

	@Override
	public void destroy() {
		filterConfig = null;
	}
}