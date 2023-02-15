package com.gdcho.security.utils;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.gdcho.security.common.APIResponse;
import com.gdcho.security.common.Status;
import com.gdcho.security.exception.BaseException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class ResponseUtil {

    /**
     * 往 response 写出 json
     *
     * @param response 响应
     * @param status   状态
     * @param data     返回数据
     */
    public static void renderJson(HttpServletResponse response,
                                  Status status,
                                  Object data) {

        try {
            response.setHeader("Access-Control-Allow-Origin",
                               "*");
            response.setHeader("Access-Control-Allow-Methods",
                               "*");
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(200);

            // FIXME: hutool 的 BUG：JSONUtil.toJsonStr()
            //  将JSON转为String的时候，忽略null值的时候转成的String存在错误
            PrintWriter writer = response.getWriter();
            writer.write(JSONUtil.toJsonStr(new JSONObject(APIResponse.ofStatus(status,
                                                                                data),
                                                           false)));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 往 response 写出 json
     *
     * @param response  响应
     * @param exception 异常
     */
    public static void renderJson(HttpServletResponse response,
                                  BaseException exception) {
        try {
            response.setHeader("Access-Control-Allow-Origin",
                               "*");
            response.setHeader("Access-Control-Allow-Methods",
                               "*");
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(200);

            // FIXME: hutool 的 BUG：JSONUtil.toJsonStr()
            //  将JSON转为String的时候，忽略null值的时候转成的String存在错误

            PrintWriter writer = response.getWriter();
            writer.write(JSONUtil.toJsonStr(new JSONObject(APIResponse.ofException(exception),
                                                           false)));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            log.error("Response写出JSON异常，",
                      e);
        }
    }

    public static void renderJson(HttpServletResponse response,
                                  Integer code,
                                  String message,
                                  Object data) {
        try {
            response.setHeader("Access-Control-Allow-Origin",
                               "*");
            response.setHeader("Access-Control-Allow-Methods",
                               "*");
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(200);

            // FIXME: hutool 的 BUG：JSONUtil.toJsonStr()
            //  将JSON转为String的时候，忽略null值的时候转成的String存在错误
            PrintWriter writer = response.getWriter();
            writer.write(JSONUtil.toJsonStr(new JSONObject(APIResponse.of(code, message, data),
                                                           false)));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            log.error("Response写出JSON异常，",
                      e);
        }
    }
}
