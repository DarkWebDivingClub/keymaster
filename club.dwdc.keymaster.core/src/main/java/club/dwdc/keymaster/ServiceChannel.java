package club.dwdc.keymaster;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * JSON dispatch wrapper for {@link AbstractServiceHandler} subclasses.
 *
 * <p>Scans {@link ServiceMethod} annotations on the handler, deserializes
 * JSON params to typed records, invokes methods, and serializes responses.
 */
public class ServiceChannel {

    private AbstractServiceHandler handler;
    private final Gson gson;
    private Map<String, MethodBinding> bindings;

    // Session-mode fields (null in direct mode)
    private final Session session;
    private final int coinType;

    record MethodBinding(Method method, Class<?> paramType) {}

    /**
     * Direct constructor — binds to a fixed handler.
     */
    public ServiceChannel(AbstractServiceHandler handler, Gson gson) {
        this.handler = handler;
        this.gson = gson;
        this.bindings = buildBindings(handler);
        this.session = null;
        this.coinType = 0;
    }

    /**
     * Session-based constructor — resolves handler lazily from the session.
     *
     * <p>On each {@link #dispatch} call, the handler is resolved via
     * {@link Session#getHandler(int)}. If the handler has changed since
     * the last call, bindings are rebuilt automatically.
     *
     * @param session  session containing handlers
     * @param coinType protocol coin type to look up
     * @param gson     Gson instance for serialization
     */
    public ServiceChannel(Session session, int coinType, Gson gson) {
        this.session = session;
        this.coinType = coinType;
        this.gson = gson;
        // Resolve handler eagerly for the initial state
        this.handler = session.getHandler(coinType);
        this.bindings = handler != null ? buildBindings(handler) : new HashMap<>();
    }

    /**
     * Dispatch a JSON-RPC-style request to the appropriate handler method.
     *
     * @param method wire name of the method (e.g. "request_identities")
     * @param params JSON array of parameters (may be null or empty)
     * @return JSON response with either {@code result} or {@code error}
     */
    public JsonObject dispatch(String method, JsonArray params) {
        // In session mode, re-resolve the handler on each call
        if (session != null) {
            AbstractServiceHandler current = session.getHandler(coinType);
            if (current == null) {
                JsonObject response = new JsonObject();
                response.addProperty("error", "no handler for coin type " + coinType);
                return response;
            }
            if (current != handler) {
                handler = current;
                bindings = buildBindings(handler);
            }
        }

        MethodBinding binding = bindings.get(method);
        if (binding == null) {
            JsonObject response = new JsonObject();
            response.addProperty("error", "unknown method: " + method);
            return response;
        }

        try {
            Object result;
            if (binding.paramType() == null) {
                result = binding.method().invoke(handler);
            } else {
                Object param = gson.fromJson(params.get(0), binding.paramType());
                result = binding.method().invoke(handler, param);
            }
            JsonObject response = new JsonObject();
            response.add("result", gson.toJsonTree(result));
            return response;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RequestDeniedException) {
                JsonObject response = new JsonObject();
                response.addProperty("error", "request denied by user");
                return response;
            }
            JsonObject response = new JsonObject();
            response.addProperty("error", cause.getMessage());
            return response;
        } catch (IllegalAccessException e) {
            JsonObject response = new JsonObject();
            response.addProperty("error", e.getMessage());
            return response;
        }
    }

    /**
     * Return the number of method bindings discovered.
     */
    int bindingCount() {
        return bindings.size();
    }

    private static Map<String, MethodBinding> buildBindings(AbstractServiceHandler handler) {
        Map<String, MethodBinding> map = new HashMap<>();
        for (Method m : handler.getClass().getDeclaredMethods()) {
            ServiceMethod ann = m.getAnnotation(ServiceMethod.class);
            if (ann != null) {
                Class<?>[] paramTypes = m.getParameterTypes();
                Class<?> paramType = paramTypes.length > 0 ? paramTypes[0] : null;
                m.setAccessible(true);
                map.put(ann.value(), new MethodBinding(m, paramType));
            }
        }
        return map;
    }

    /**
     * Create a Gson instance configured for the service wire format:
     * snake_case field naming and Base64 encoding for byte arrays.
     */
    public static Gson createGson() {
        return new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .registerTypeAdapter(byte[].class, new Base64TypeAdapter())
                .create();
    }

    /**
     * Gson TypeAdapter that serializes/deserializes {@code byte[]} as Base64 strings.
     */
    static class Base64TypeAdapter extends TypeAdapter<byte[]> {
        @Override
        public void write(JsonWriter out, byte[] value) throws IOException {
            if (value == null) {
                out.nullValue();
            } else {
                out.value(Base64.getEncoder().encodeToString(value));
            }
        }

        @Override
        public byte[] read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NULL) {
                in.nextNull();
                return null;
            }
            return Base64.getDecoder().decode(in.nextString());
        }
    }
}
