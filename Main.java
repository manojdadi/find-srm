import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * SRM FIND - Campus Lost and Found (Web version)
 *
 * Same model as the console version (Item, LostItem, FoundItem,
 * Repository, Storage, matching score), but instead of a Scanner menu
 * it runs a small web server using Java's built-in HttpServer.
 *
 * Run:   javac Main.java && java Main
 * Open:  http://localhost:8080
 */

// ---------- ENUMS ----------
enum Category {
    ELECTRONICS, IDENTITY_CARDS, BOOKS, CLOTHING,
    ACCESSORIES, OTHER
}

enum Status {
    ACTIVE, RESOLVED
}

// ---------- INTERFACE ----------
interface Searchable {
    boolean matches(String keyword);
}

// ---------- CUSTOM EXCEPTION ----------
class InvalidReportException extends Exception {
    InvalidReportException(String message) {
        super(message);
    }
}

// ---------- ABSTRACT CLASS ----------
abstract class Item implements Serializable, Searchable {
    private static final long serialVersionUID = 1L;

    protected String id, name, description, location;
    protected String email, studentName, date;
    protected Category category;
    protected Status status;
    protected String photo;   // file name inside data/photos (or null)

    Item(String id, String name, String description,
         String location, String studentName,
         String email, Category category) {

        this.id = id;
        this.name = name;
        this.description = description;
        this.location = location;
        this.studentName = studentName;
        this.email = email;
        this.category = category;
        this.status = Status.ACTIVE;

        date = LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm")
        );
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public String getLocation() { return location; }
    public Category getCategory() { return category; }
    public Status getStatus() { return status; }

    public void setName(String name) { this.name = name; }
    public void setDescription(String d) { description = d; }
    public void setLocation(String l) { location = l; }

    public void resolve() {
        status = Status.RESOLVED;
    }

    public boolean matches(String key) {
        key = key.toLowerCase();

        return name.toLowerCase().contains(key)
            || description.toLowerCase().contains(key)
            || location.toLowerCase().contains(key)
            || id.toLowerCase().contains(key);
    }

    abstract String getType();

    // Web version of display(): turns the item into JSON
    String toJson(String currentEmail) {
        return "{"
            + "\"id\":" + Json.q(id) + ","
            + "\"type\":" + Json.q(getType()) + ","
            + "\"name\":" + Json.q(name) + ","
            + "\"category\":" + Json.q(category.name()) + ","
            + "\"description\":" + Json.q(description) + ","
            + "\"location\":" + Json.q(location) + ","
            + "\"student\":" + Json.q(studentName) + ","
            + "\"email\":" + Json.q(email) + ","
            + "\"date\":" + Json.q(date) + ","
            + "\"status\":" + Json.q(status.name()) + ","
            + "\"photo\":" + (photo == null ? "null" : Json.q("/photos/" + photo)) + ","
            + "\"mine\":" + email.equalsIgnoreCase(currentEmail)
            + "}";
    }
}

// ---------- LOST ITEM ----------
class LostItem extends Item {
    private static final long serialVersionUID = 1L;

    LostItem(String id, String n, String d, String l,
             String s, String e, Category c) {
        super(id, n, d, l, s, e, c);
    }

    String getType() {
        return "LOST";
    }
}

// ---------- FOUND ITEM ----------
class FoundItem extends Item {
    private static final long serialVersionUID = 1L;

    FoundItem(String id, String n, String d, String l,
              String s, String e, Category c) {
        super(id, n, d, l, s, e, c);
    }

    String getType() {
        return "FOUND";
    }
}

// ---------- USER (for login) ----------
class User implements Serializable {
    private static final long serialVersionUID = 1L;

    String name, email, salt, passwordHash;

    User(String name, String email, String password) {
        this.name = name;
        this.email = email.toLowerCase();
        this.salt = randomToken();
        this.passwordHash = hash(password, salt);
    }

    boolean checkPassword(String password) {
        return passwordHash.equals(hash(password, salt));
    }

    static String randomToken() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    static String hash(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest((salt + password).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

// ---------- GENERIC REPOSITORY ----------
class Repository<T extends Item> implements Serializable {
    private static final long serialVersionUID = 1L;

    ArrayList<T> items = new ArrayList<>();
    HashMap<String, T> index = new HashMap<>();

    void add(T item) {
        items.add(item);
        index.put(item.getId(), item);
    }

    T get(String id) {
        return index.get(id.toUpperCase());
    }

    void remove(T item) {
        items.remove(item);
        index.remove(item.getId());
    }
}

// ---------- SAVED DATA ----------
class Storage implements Serializable {
    private static final long serialVersionUID = 1L;

    Repository<Item> repository = new Repository<>();
    HashMap<String, User> users = new HashMap<>();

    // Two-party handshake: "L101|F102" -> emails that have confirmed the handover
    HashMap<String, HashSet<String>> confirmations = new HashMap<>();
    int counter = 100;

    // secret used to sign login cookies (created once, saved with the data)
    String sessionSecret;
}

// ---------- VERCEL BLOB STORAGE ----------
// On Vercel the server's own disk is temporary, so the data file and photos are
// kept in a private Vercel Blob store instead. Used only when BLOB_READ_WRITE_TOKEN is set.
class BlobStore {
    static final String API = "https://vercel.com/api/blob";

    final String token, storeId;
    final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    String dataEtag;   // version of the data file this server last saw

    static BlobStore fromEnv() {
        String t = System.getenv("BLOB_READ_WRITE_TOKEN");
        return (t == null || t.isBlank()) ? null : new BlobStore(t.trim());
    }

    BlobStore(String token) {
        this.token = token;
        String[] parts = token.split("_");      // vercel_blob_rw_<storeId>_<secret>
        this.storeId = parts.length > 3 ? parts[3] : "";
    }

    String url(String pathname) {
        return "https://" + storeId + ".private.blob.vercel-storage.com/" + pathname;
    }

    HttpResponse<byte[]> get(String pathname, String ifNoneMatch, boolean fresh) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url(pathname) + (fresh ? "?cache=0" : "")))
            .header("Authorization", "Bearer " + token)
            .timeout(Duration.ofSeconds(20)).GET();
        if (ifNoneMatch != null) b.header("If-None-Match", ifNoneMatch);
        return send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    // uploads (or overwrites) a file; returns its new etag.
    // ifMatch makes the write fail if someone else changed the file meanwhile.
    String put(String pathname, byte[] body, String contentType, String ifMatch) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(
                URI.create(API + "/?pathname=" + URLEncoder.encode(pathname, StandardCharsets.UTF_8)))
            .header("Authorization", "Bearer " + token)
            .header("x-api-version", "13")
            .header("x-vercel-blob-store-id", storeId)
            .header("x-vercel-blob-access", "private")
            .header("x-add-random-suffix", "0")
            .header("x-allow-overwrite", "1")
            .header("x-content-type", contentType)
            .timeout(Duration.ofSeconds(30))
            .PUT(HttpRequest.BodyPublishers.ofByteArray(body));
        if (ifMatch != null) b.header("x-if-match", ifMatch);

        HttpResponse<String> r = send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() == 412 || r.body().contains("precondition_failed"))
            throw new HttpError(409, "Someone else just updated the portal. Please try again.");
        if (r.statusCode() / 100 != 2)
            throw new IOException("Blob upload failed (" + r.statusCode() + "): " + r.body());

        Matcher m = Pattern.compile("\"etag\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"").matcher(r.body());
        return m.find() ? m.group(1).replace("\\\"", "\"") : null;
    }

    void delete(String pathname) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(API + "/delete"))
                .header("Authorization", "Bearer " + token)
                .header("x-api-version", "13")
                .header("x-vercel-blob-store-id", storeId)
                .header("content-type", "application/json")
                .timeout(Duration.ofSeconds(20))
                .POST(HttpRequest.BodyPublishers.ofString("{\"urls\":[" + Json.q(url(pathname)) + "]}"))
                .build();
            send(req, HttpResponse.BodyHandlers.discarding());
        } catch (IOException e) {
            System.out.println("Photo delete failed: " + e.getMessage());
        }
    }

    <T> HttpResponse<T> send(HttpRequest req, HttpResponse.BodyHandler<T> handler) throws IOException {
        try {
            return http.send(req, handler);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
    }
}

// ---------- SMALL JSON HELPER ----------
class Json {
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    static String error(String message) {
        return "{\"error\":" + q(message) + "}";
    }
}

// Thrown inside request handlers to send an error response
class HttpError extends RuntimeException {
    int code;
    HttpError(int code, String message) {
        super(message);
        this.code = code;
    }
}

// ---------- MAIN CLASS ----------
public class Main {

    static Storage data = new Storage();

    // Everything saved lives in the "data" folder:
    //   data/srmfind.dat   - the real database (Java serialized, not human readable)
    //   data/reports.csv   - readable copy of all reports (open in Excel / Numbers)
    //   data/users.csv     - readable list of registered users (no passwords)
    //   data/photos/       - uploaded item photos
    static final Path DATA_DIR = Paths.get(
        System.getenv().getOrDefault("DATA_DIR", "data")).toAbsolutePath().normalize();
    static final Path PHOTO_DIR = DATA_DIR.resolve("photos");
    static final String FILE = DATA_DIR.resolve("srmfind.dat").toString();
    static final Path PUBLIC_DIR = Paths.get("public").toAbsolutePath().normalize();
    static final int MAX_PHOTO_BYTES = 5 * 1024 * 1024;
    static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));

    // Vercel Blob storage (null when running locally -> use the data folder)
    static final BlobStore blob = BlobStore.fromEnv();
    static final String DATA_BLOB = "srmfind/srmfind.dat";
    static final String PHOTO_BLOB = "srmfind/photos/";

    // ---------- FILE HANDLING ----------
    static void saveData() {
        if (blob != null) {
            try {
                blob.dataEtag = blob.put(DATA_BLOB, serialize(data), "application/octet-stream", blob.dataEtag);
            } catch (HttpError e) {
                blob.dataEtag = null;   // our copy is out of date: reload it on the next request
                throw e;
            } catch (IOException e) {
                e.printStackTrace();
                blob.dataEtag = null;
                throw new HttpError(503, "Data could not be saved. Please try again.");
            }
            return;
        }
        try (ObjectOutputStream out =
                 new ObjectOutputStream(new FileOutputStream(FILE))) {
            out.writeObject(data);
        } catch (IOException e) {
            System.out.println("Data could not be saved.");
        }
        exportCsv();
    }

    static byte[] serialize(Storage s) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(s);
        }
        return bytes.toByteArray();
    }

    static Storage deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return (Storage) in.readObject();
        }
    }

    // fields added in newer versions are null in older saved files
    static void fixOldData() {
        if (data.users == null) data.users = new HashMap<>();
        if (data.confirmations == null) data.confirmations = new HashMap<>();
    }

    // Blob mode: re-read the data file if another server instance changed it.
    // The If-None-Match check makes this a tiny request when nothing changed.
    static void refreshFromBlob() throws IOException {
        HttpResponse<byte[]> r = blob.get(DATA_BLOB, blob.dataEtag, true);
        if (r.statusCode() == 304 || r.statusCode() == 404) return;   // unchanged / nothing saved yet
        if (r.statusCode() != 200)
            throw new IOException("Could not load data from Blob (" + r.statusCode() + ")");
        try {
            data = deserialize(r.body());
        } catch (ClassNotFoundException e) {
            throw new IOException(e);
        }
        fixOldData();
        blob.dataEtag = r.headers().firstValue("etag").orElse(null);
    }

    // readable copies of the data, so you can open them in Excel / Numbers
    static void exportCsv() {
        StringBuilder r = new StringBuilder(
            "ID,Type,Item,Category,Description,Location,Student,Email,Date,Status,Photo\n");
        for (Item i : data.repository.items) {
            r.append(String.join(",", csv(i.id), csv(i.getType()), csv(i.name),
                csv(i.category.name()), csv(i.description), csv(i.location),
                csv(i.studentName), csv(i.email), csv(i.date), csv(i.status.name()),
                csv(i.photo == null ? "" : "photos/" + i.photo))).append('\n');
        }
        StringBuilder u = new StringBuilder("Name,Email\n");
        for (User user : data.users.values())
            u.append(csv(user.name)).append(',').append(csv(user.email)).append('\n');
        try {
            Files.writeString(DATA_DIR.resolve("reports.csv"), r.toString());
            Files.writeString(DATA_DIR.resolve("users.csv"), u.toString());
        } catch (IOException e) {
            System.out.println("CSV export failed: " + e.getMessage());
        }
    }

    static String csv(String s) {
        if (s == null) s = "";
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    // ---------- PHOTOS ----------
    // The browser sends the photo as a data URL: "data:image/jpeg;base64,...."
    static void savePhoto(Item item, String dataUrl) throws IOException {
        if (dataUrl == null || dataUrl.isEmpty()) return;

        String ext;
        if (dataUrl.startsWith("data:image/jpeg;base64,")) ext = "jpg";
        else if (dataUrl.startsWith("data:image/png;base64,")) ext = "png";
        else if (dataUrl.startsWith("data:image/webp;base64,")) ext = "webp";
        else throw new HttpError(400, "Photo must be a JPG, PNG or WEBP image.");

        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(dataUrl.substring(dataUrl.indexOf(',') + 1));
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, "Photo could not be read.");
        }
        if (bytes.length > MAX_PHOTO_BYTES)
            throw new HttpError(400, "Photo is too large (max 5 MB).");

        deletePhoto(item); // replace the old one, if any
        String fileName = item.getId() + "-" + System.currentTimeMillis() + "." + ext;
        if (blob != null)
            blob.put(PHOTO_BLOB + fileName, bytes, ext.equals("jpg") ? "image/jpeg" : "image/" + ext, null);
        else
            Files.write(PHOTO_DIR.resolve(fileName), bytes);
        item.photo = fileName;
    }

    static void deletePhoto(Item item) {
        if (item.photo == null) return;
        if (blob != null) blob.delete(PHOTO_BLOB + item.photo);
        else try { Files.deleteIfExists(PHOTO_DIR.resolve(item.photo)); } catch (IOException ignored) {}
        item.photo = null;
    }

    static void loadData() {
        if (blob != null) {
            try {
                refreshFromBlob();
            } catch (IOException e) {
                System.out.println("Could not load data from Vercel Blob: " + e.getMessage());
            }
        } else {
            try (ObjectInputStream in =
                     new ObjectInputStream(new FileInputStream(FILE))) {
                data = (Storage) in.readObject();
            } catch (Exception e) {
                data = new Storage();
            }
        }
        fixOldData();

        if (data.sessionSecret == null) {
            data.sessionSecret = User.randomToken() + User.randomToken();
            try { saveData(); } catch (HttpError e) { System.out.println(e.getMessage()); }
        }
    }

    // ---------- VALIDATION ----------
    static boolean validEmail(String email) {
        return email.matches("^[A-Za-z0-9._%+-]+@.*\\.edu(\\.in)?$");
    }

    static String required(Map<String, String> p, String key, String label) {
        String v = p.getOrDefault(key, "").trim();
        if (v.isEmpty()) throw new HttpError(400, label + " cannot be empty!");
        return v;
    }

    static Category parseCategory(String c) {
        try {
            return Category.valueOf(c.toUpperCase());
        } catch (Exception e) {
            throw new HttpError(400, "Invalid category!");
        }
    }

    // ---------- MATCHING SYSTEM (same as console version) ----------
    static int calculateMatch(Item a, Item b) {

        if (a.getType().equals(b.getType())
            || a.getCategory() != b.getCategory())
            return 0;

        int score = 40;

        String n1 = a.getName().toLowerCase();
        String n2 = b.getName().toLowerCase();

        if (n1.equals(n2))
            score += 40;
        else if (n1.contains(n2) || n2.contains(n1))
            score += 20;

        if (a.getLocation().equalsIgnoreCase(b.getLocation()))
            score += 20;

        return score;
    }

    // One match as JSON, with the score breakdown and the handshake state
    static String matchJson(Item item, Item other, String me) {
        String n1 = item.getName().toLowerCase(), n2 = other.getName().toLowerCase();
        int namePts = n1.equals(n2) ? 40 : (n1.contains(n2) || n2.contains(n1)) ? 20 : 0;
        int locPts = item.getLocation().equalsIgnoreCase(other.getLocation()) ? 20 : 0;

        Item lost = item.getType().equals("LOST") ? item : other;
        Item found = lost == item ? other : item;
        Set<String> confirmed = data.confirmations.getOrDefault(pairKey(lost, found), new HashSet<>());

        return "{\"score\":" + calculateMatch(item, other)
            + ",\"category\":40,\"name\":" + namePts + ",\"location\":" + locPts
            + ",\"lostId\":" + Json.q(lost.getId()) + ",\"foundId\":" + Json.q(found.getId())
            + ",\"ownerConfirmed\":" + confirmed.contains(lost.getEmail().toLowerCase())
            + ",\"finderConfirmed\":" + confirmed.contains(found.getEmail().toLowerCase())
            + ",\"item\":" + other.toJson(me) + "}";
    }

    static List<Item> matchesFor(Item item) {
        List<Item> list = new ArrayList<>();
        for (Item other : data.repository.items) {
            if (other == item || other.getStatus() != Status.ACTIVE) continue;
            if (calculateMatch(item, other) >= 60) list.add(other);
        }
        list.sort(Comparator.comparingInt((Item o) -> calculateMatch(item, o)).reversed());
        return list;
    }

    static String matchesJson(Item item, String me) {
        StringBuilder sb = new StringBuilder("[");
        for (Item other : matchesFor(item)) {
            if (sb.length() > 1) sb.append(',');
            sb.append(matchJson(item, other, me));
        }
        return sb.append(']').toString();
    }

    // ---------- TWO-PARTY HANDSHAKE ----------
    static String pairKey(Item lost, Item found) {
        return lost.getId() + "|" + found.getId();
    }

    // forget handshakes whose reports were deleted or resolved
    static void pruneConfirmations() {
        data.confirmations.keySet().removeIf(key -> {
            String[] ids = key.split("\\|");
            Item a = data.repository.get(ids[0]), b = data.repository.get(ids[1]);
            return a == null || b == null
                || a.getStatus() != Status.ACTIVE || b.getStatus() != Status.ACTIVE;
        });
    }

    // ---------- REGISTER REPORT ----------
    static Item register(boolean lost, Map<String, String> p, User user)
            throws InvalidReportException, IOException {

        String name = required(p, "name", "Item name");
        String description = required(p, "description", "Description");
        String location = required(p, "location", "Location");
        Category category = parseCategory(required(p, "category", "Category"));

        for (Item item : data.repository.items) {
            if (item.getStatus() == Status.ACTIVE
                && item.getType().equals(lost ? "LOST" : "FOUND")
                && item.getName().equalsIgnoreCase(name)
                && item.getEmail().equalsIgnoreCase(user.email)) {

                throw new InvalidReportException(
                    "Similar active report already exists!"
                );
            }
        }

        String id = (lost ? "L" : "F") + (++data.counter);

        Item item = lost
            ? new LostItem(id, name, description, location, user.name, user.email, category)
            : new FoundItem(id, name, description, location, user.name, user.email, category);

        savePhoto(item, p.get("photo"));
        data.repository.add(item);
        saveData();
        return item;
    }

    static Item ownedActiveItem(Map<String, String> p, User user) {
        Item item = data.repository.get(required(p, "id", "Report ID"));
        if (item == null) throw new HttpError(404, "Report not found.");
        if (!item.getEmail().equalsIgnoreCase(user.email))
            throw new HttpError(403, "You can only change your own reports.");
        return item;
    }

    // ---------- API ROUTES ----------
    static String api(HttpExchange ex, String path, Map<String, String> p) throws Exception {

        // --- public routes ---
        switch (path) {
            case "/api/signup": {
                String name = required(p, "name", "Name");
                String email = required(p, "email", "Email").toLowerCase();
                String password = required(p, "password", "Password");
                if (!validEmail(email))
                    throw new HttpError(400, "Enter a valid college email address (ending in .edu or .edu.in).");
                if (password.length() < 6)
                    throw new HttpError(400, "Password must be at least 6 characters.");
                if (data.users.containsKey(email))
                    throw new HttpError(400, "An account with this email already exists. Please log in.");
                User u = new User(name, email, password);
                data.users.put(email, u);
                saveData();
                startSession(ex, u);
                return userJson(u);
            }
            case "/api/login": {
                String email = required(p, "email", "Email").toLowerCase();
                String password = required(p, "password", "Password");
                User u = data.users.get(email);
                if (u == null || !u.checkPassword(password))
                    throw new HttpError(401, "Wrong email or password.");
                startSession(ex, u);
                return userJson(u);
            }
            case "/api/logout": {
                ex.getResponseHeaders().add("Set-Cookie", "sid=; Path=/; Max-Age=0");
                return "{\"ok\":true}";
            }
        }

        // --- everything below needs login ---
        User user = currentUser(ex);
        if (user == null) throw new HttpError(401, "Please log in first.");

        switch (path) {
            case "/api/me":
                return userJson(user);

            // VIEW / SEARCH / FILTER / SORT
            case "/api/items": {
                String q = p.getOrDefault("q", "").trim();
                String cat = p.getOrDefault("category", "");
                String type = p.getOrDefault("type", "");
                String status = p.getOrDefault("status", "");
                boolean mine = "1".equals(p.get("mine"));

                // A report ID like "L101" is looked up directly in the HashMap: O(1)
                List<Item> source = data.repository.items;
                if (q.matches("(?i)[LF]\\d+")) {
                    Item hit = data.repository.get(q);
                    if (hit != null) source = List.of(hit);
                }

                ArrayList<Item> list = new ArrayList<>();
                for (Item item : source) {
                    if (!q.isEmpty() && !item.matches(q)) continue;
                    if (!cat.isEmpty() && !item.getCategory().name().equals(cat)) continue;
                    if (!type.isEmpty() && !item.getType().equals(type)) continue;
                    if (!status.isEmpty() && !item.getStatus().name().equals(status)) continue;
                    if (mine && !item.getEmail().equalsIgnoreCase(user.email)) continue;
                    list.add(item);
                }

                if ("name".equals(p.get("sort")))
                    list.sort(Comparator.comparing(i -> i.getName().toLowerCase()));
                else
                    Collections.reverse(list); // newest first

                StringBuilder sb = new StringBuilder("[");
                for (Item i : list) {
                    if (sb.length() > 1) sb.append(',');
                    sb.append(i.toJson(user.email));
                }
                return sb.append(']').toString();
            }

            // REPORT LOST / FOUND
            case "/api/report": {
                String type = required(p, "type", "Type");
                try {
                    Item item = register(type.equals("LOST"), p, user);
                    return "{\"item\":" + item.toJson(user.email)
                        + ",\"matches\":" + matchesJson(item, user.email) + "}";
                } catch (InvalidReportException e) {
                    throw new HttpError(400, e.getMessage());
                }
            }

            // CHECK MATCHES for one item
            case "/api/matches": {
                Item item = data.repository.get(required(p, "id", "Report ID"));
                if (item == null) throw new HttpError(404, "Report not found.");
                return matchesJson(item, user.email);
            }

            // EDIT
            case "/api/edit": {
                Item item = ownedActiveItem(p, user);
                if (item.getStatus() != Status.ACTIVE)
                    throw new HttpError(400, "Resolved reports cannot be edited.");
                item.setName(required(p, "name", "Item name"));
                item.setDescription(required(p, "description", "Description"));
                item.setLocation(required(p, "location", "Location"));
                if ("1".equals(p.get("removePhoto"))) deletePhoto(item);
                savePhoto(item, p.get("photo"));
                saveData();
                return item.toJson(user.email);
            }

            // DELETE
            case "/api/delete": {
                Item item = ownedActiveItem(p, user);
                deletePhoto(item);
                data.repository.remove(item);
                pruneConfirmations();
                saveData();
                return "{\"ok\":true}";
            }

            // CLOSE: owner closes their own report on its own
            // (e.g. got it back outside the portal)
            case "/api/resolve": {
                Item mineItem = ownedActiveItem(p, user);
                if (mineItem.getStatus() != Status.ACTIVE)
                    throw new HttpError(400, "This report is already resolved.");
                mineItem.resolve();
                pruneConfirmations();
                saveData();
                return "{\"ok\":true}";
            }

            // TWO-PARTY HANDSHAKE
            // 1. match detected (>= 60%)  2. each side confirms with their registered email
            // 3. emails verified  4. score re-checked  5. both reports RESOLVED together
            case "/api/confirm": {
                Item lost = data.repository.get(required(p, "lost", "LOST report ID"));
                Item found = data.repository.get(required(p, "found", "FOUND report ID"));

                if (lost == null || !lost.getType().equals("LOST") || lost.getStatus() != Status.ACTIVE)
                    throw new HttpError(404, "Active LOST report not found.");
                if (found == null || !found.getType().equals("FOUND") || found.getStatus() != Status.ACTIVE)
                    throw new HttpError(404, "Active FOUND report not found.");
                if (calculateMatch(lost, found) < 60)
                    throw new HttpError(400, "These reports do not meet the matching criteria (60%).");

                String ownerEmail = lost.getEmail().toLowerCase();
                String finderEmail = found.getEmail().toLowerCase();
                String myEmail = user.email.toLowerCase();
                if (!myEmail.equals(ownerEmail) && !myEmail.equals(finderEmail))
                    throw new HttpError(403, "Verification failed! Only the owner or the finder can confirm this handover.");

                String key = pairKey(lost, found);
                HashSet<String> confirmed = data.confirmations.computeIfAbsent(key, k -> new HashSet<>());
                confirmed.add(myEmail);

                if (confirmed.contains(ownerEmail) && confirmed.contains(finderEmail)) {
                    // re-verify before the atomic status change
                    if (calculateMatch(lost, found) < 60)
                        throw new HttpError(400, "These reports no longer match.");
                    lost.resolve();
                    found.resolve();
                    pruneConfirmations();
                    saveData();
                    return "{\"status\":\"RESOLVED\"}";
                }

                saveData();
                String waitingFor = myEmail.equals(ownerEmail) ? "finder" : "owner";
                return "{\"status\":\"PENDING\",\"waitingFor\":\"" + waitingFor + "\"}";
            }

            case "/api/decline": {
                Item lost = data.repository.get(required(p, "lost", "LOST report ID"));
                Item found = data.repository.get(required(p, "found", "FOUND report ID"));
                if (lost == null || found == null) throw new HttpError(404, "Report not found.");
                String myEmail = user.email.toLowerCase();
                if (!myEmail.equalsIgnoreCase(lost.getEmail()) && !myEmail.equalsIgnoreCase(found.getEmail()))
                    throw new HttpError(403, "Only the owner or the finder can do this.");
                data.confirmations.remove(pairKey(lost, found));
                saveData();
                return "{\"ok\":true}";
            }

            // NOTIFICATIONS: matches on my reports + handovers waiting for me
            case "/api/notifications": {
                StringBuilder sb = new StringBuilder("[");
                String myEmail = user.email.toLowerCase();
                for (Item mineItem : data.repository.items) {
                    if (!mineItem.getEmail().equalsIgnoreCase(myEmail)
                        || mineItem.getStatus() != Status.ACTIVE) continue;

                    for (Item other : matchesFor(mineItem)) {
                        if (other.getEmail().equalsIgnoreCase(myEmail)) continue;
                        Item lost = mineItem.getType().equals("LOST") ? mineItem : other;
                        Item found = lost == mineItem ? other : mineItem;
                        Set<String> c = data.confirmations.getOrDefault(pairKey(lost, found), new HashSet<>());

                        String kind = c.contains(myEmail) ? "waiting"
                                    : c.contains(other.getEmail().toLowerCase()) ? "confirm"
                                    : "match";
                        if (sb.length() > 1) sb.append(',');
                        sb.append("{\"kind\":\"").append(kind).append("\",\"mine\":")
                          .append(mineItem.toJson(myEmail)).append(",\"match\":")
                          .append(matchJson(mineItem, other, myEmail)).append('}');
                    }
                }
                return sb.append(']').toString();
            }

            // DASHBOARD
            case "/api/stats": {
                int lost = 0, found = 0, resolved = 0, active = 0;
                for (Item item : data.repository.items) {
                    if (item.getType().equals("LOST")) lost++; else found++;
                    if (item.getStatus() == Status.RESOLVED) resolved++; else active++;
                }
                return "{\"total\":" + data.repository.items.size()
                    + ",\"lost\":" + lost + ",\"found\":" + found
                    + ",\"active\":" + active + ",\"resolved\":" + resolved + "}";
            }
        }

        throw new HttpError(404, "Unknown API route.");
    }

    // ---------- SESSIONS ----------
    // The login cookie is "email.expiry.signature", signed with a secret only the
    // server knows. Nothing is kept in memory, so it works across server restarts.
    static final long SESSION_SECONDS = 7 * 24 * 3600;

    static String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(data.sessionSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static void startSession(HttpExchange ex, User u) {
        long expires = System.currentTimeMillis() / 1000 + SESSION_SECONDS;
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(u.email.getBytes(StandardCharsets.UTF_8)) + "." + expires;
        String secure = blob != null ? "; Secure" : "";
        ex.getResponseHeaders().add("Set-Cookie", "sid=" + payload + "." + sign(payload)
            + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + SESSION_SECONDS + secure);
    }

    static String sessionToken(HttpExchange ex) {
        List<String> cookies = ex.getRequestHeaders().get("Cookie");
        if (cookies == null) return null;
        for (String header : cookies)
            for (String c : header.split(";")) {
                String[] kv = c.trim().split("=", 2);
                if (kv.length == 2 && kv[0].equals("sid")) return kv[1];
            }
        return null;
    }

    static User currentUser(HttpExchange ex) {
        String token = sessionToken(ex);
        if (token == null) return null;
        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;
        String payload = parts[0] + "." + parts[1];
        if (!MessageDigest.isEqual(sign(payload).getBytes(StandardCharsets.UTF_8),
                                   parts[2].getBytes(StandardCharsets.UTF_8))) return null;
        try {
            if (Long.parseLong(parts[1]) < System.currentTimeMillis() / 1000) return null;   // expired
            String email = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            return data.users.get(email);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static String userJson(User u) {
        return "{\"name\":" + Json.q(u.name) + ",\"email\":" + Json.q(u.email) + "}";
    }

    // ---------- HTTP PLUMBING ----------
    static Map<String, String> params(HttpExchange ex) throws IOException {
        Map<String, String> p = new HashMap<>();
        parseInto(p, ex.getRequestURI().getRawQuery());
        if ("POST".equals(ex.getRequestMethod())) {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            parseInto(p, body);
        }
        return p;
    }

    static void parseInto(Map<String, String> p, String s) {
        if (s == null || s.isEmpty()) return;
        for (String pair : s.split("&")) {
            String[] kv = pair.split("=", 2);
            String k = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String v = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            p.put(k, v);
        }
    }

    static void send(HttpExchange ex, int code, String type, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    static void serveFile(HttpExchange ex, String path) throws IOException {
        if (path.equals("/")) path = "/index.html";

        // photos stored in Vercel Blob are private, so the server streams them out
        if (blob != null && path.startsWith("/photos/")) {
            String name = path.substring("/photos/".length());
            if (!name.matches("[A-Za-z0-9.-]+")) { send(ex, 404, "text/plain", "Not found".getBytes()); return; }
            HttpResponse<byte[]> r = blob.get(PHOTO_BLOB + name, null, false);
            if (r.statusCode() != 200) { send(ex, 404, "text/plain", "Not found".getBytes()); return; }
            ex.getResponseHeaders().set("Cache-Control", "private, max-age=31536000, immutable");
            send(ex, 200, r.headers().firstValue("content-type").orElse("image/jpeg"), r.body());
            return;
        }

        Path dir = PUBLIC_DIR;
        if (path.startsWith("/photos/")) {      // uploaded photos
            dir = PHOTO_DIR;
            path = path.substring("/photos".length());
        }
        Path file = dir.resolve(path.substring(1)).normalize();
        if (!file.startsWith(dir) || !Files.isRegularFile(file)) {
            send(ex, 404, "text/plain", "Not found".getBytes());
            return;
        }
        String name = file.toString();
        String type = name.endsWith(".html") ? "text/html; charset=utf-8"
                    : name.endsWith(".css") ? "text/css"
                    : name.endsWith(".js") ? "application/javascript"
                    : name.endsWith(".svg") ? "image/svg+xml"
                    : name.endsWith(".jpg") ? "image/jpeg"
                    : name.endsWith(".png") ? "image/png"
                    : name.endsWith(".webp") ? "image/webp"
                    : "application/octet-stream";
        send(ex, 200, type, Files.readAllBytes(file));
    }

    // one request at a time keeps the shared data safe
    static synchronized void handle(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        try {
            if (path.startsWith("/api/")) {
                if (blob != null) {
                    try {
                        refreshFromBlob();   // pick up changes made by other server instances
                    } catch (IOException e) {
                        e.printStackTrace();
                        throw new HttpError(503, "Storage is not reachable right now. Please try again.");
                    }
                }
                String json = api(ex, path, params(ex));
                send(ex, 200, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8));
            } else {
                serveFile(ex, path);
            }
        } catch (HttpError e) {
            send(ex, e.code, "application/json; charset=utf-8",
                 Json.error(e.getMessage()).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
            send(ex, 500, "application/json; charset=utf-8",
                 Json.error("Server error").getBytes(StandardCharsets.UTF_8));
        }
    }

    // ---------- MAIN ----------
    public static void main(String[] args) throws IOException {
        if (blob == null) {
            Files.createDirectories(PHOTO_DIR);

            // older versions saved srmfind.dat next to Main.java - move it into data/
            Path oldFile = Paths.get("srmfind.dat");
            if (System.getenv("DATA_DIR") == null
                && Files.exists(oldFile) && !Files.exists(Paths.get(FILE)))
                Files.move(oldFile, Paths.get(FILE));
        }

        loadData();
        if (blob == null) exportCsv();

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", Main::handle);
        server.start();

        System.out.println("================================");
        System.out.println("       SRM FIND PORTAL");
        System.out.println("  Campus Lost and Found System");
        System.out.println("================================");
        System.out.println("Storage: " + (blob != null ? "Vercel Blob (private)" : "local folder " + DATA_DIR));
        System.out.println("Server running at http://localhost:" + PORT);
        System.out.println("Press Ctrl+C to stop.");
    }
}
