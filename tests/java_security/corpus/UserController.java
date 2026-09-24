package com.acme.web;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.net.URI;
import java.nio.file.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final UserService service;
    private final RestTemplate restTemplate;

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> get(@PathVariable Long id) {
        log.info("fetching user {}", id);
        return ResponseEntity.ok(service.find(id));
    }

    @GetMapping("/search")
    public List<UserDto> search(@RequestParam String name, @RequestParam(defaultValue = "0") int page) {
        return service.search(name, PageRequest.of(page, 20, Sort.by("name")));
    }

    @PostMapping
    public ResponseEntity<UserDto> create(@RequestBody @Valid CreateUser body) {
        UserDto created = service.create(body);
        return ResponseEntity.created(URI.create("/api/users/" + created.id())).body(created);
    }

    @GetMapping("/{id}/avatar")
    public byte[] avatar(@PathVariable Long id) throws Exception {
        Path base = Paths.get("/srv/avatars");
        return Files.readAllBytes(base.resolve(id + ".png"));
    }

    @GetMapping("/weather")
    public String weather(@RequestParam String city) {
        String url = UriComponentsBuilder.fromHttpUrl("https://api.weather.example/v1").queryParam("city", city).toUriString();
        return restTemplate.getForObject("https://api.weather.example/v1?city={city}", String.class, city);
    }

    @GetMapping("/export")
    public void export(HttpServletResponse response) throws IOException {
        response.setContentType("text/csv");
        response.getWriter().write(service.csv());
    }
}
