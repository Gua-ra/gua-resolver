package global.gua.resolver.api;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.admission.AdmissionRequest;
import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.admission.MemberAttestationRequest;
import global.gua.resolver.roster.MemberEntryJson;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.SignedRoster;

/** {@code /authority/**} requires the ADMIN role, enforced in SecurityConfig. */
@RestController
@RequestMapping("/authority")
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class AdmissionController {

    private final AdmissionService admission;
    private final ObjectMapper json;
    private final Validator validator;

    public AdmissionController(AdmissionService admission, ObjectMapper json, Validator validator) {
        this.admission = admission;
        this.json = json;
        this.validator = validator;
    }

    @PostMapping(path = "/admission", consumes = MediaType.APPLICATION_JSON_VALUE)
    public SignedRoster admit(@RequestBody byte[] body) {
        return admission.admit(parseAdmission(body));
    }

    @PostMapping(path = "/roster/{id}/member", consumes = MediaType.APPLICATION_JSON_VALUE)
    public SignedRoster attest(@PathVariable String id, @RequestBody byte[] body) {
        return admission.attest(id, MemberEntryJson.read(json, body, MemberAttestationRequest.class));
    }

    @PostMapping("/roster/{id}/status")
    public SignedRoster setStatus(@PathVariable String id, @RequestParam RosterEntry.Status status) {
        return admission.setStatus(id, status);
    }

    private AdmissionRequest parseAdmission(byte[] body) {
        JsonNode tree = MemberEntryJson.readTree(json, body);
        AdmissionRequest request = tree.hasNonNull("member")
                ? MemberEntryJson.read(json, body, AdmissionRequest.class)
                : lenient(body);
        Set<ConstraintViolation<AdmissionRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new AdmissionService.AdmissionException("invalid admission request: "
                    + violations.stream()
                    .map(v -> v.getPropertyPath() + " " + v.getMessage())
                    .sorted()
                    .collect(Collectors.joining(", ")));
        }
        return request;
    }

    private AdmissionRequest lenient(byte[] body) {
        try {
            return json.readValue(body, AdmissionRequest.class);
        } catch (IOException e) {
            throw new MemberEntryJson.MalformedMemberEntryException("malformed admission request");
        }
    }

    @ExceptionHandler(AdmissionService.AdmissionException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onAdmissionError(AdmissionService.AdmissionException e) {
        return new ProblemResponse("admission_rejected", e.getMessage());
    }

    @ExceptionHandler(MemberEntryJson.MalformedMemberEntryException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onMalformedBody(MemberEntryJson.MalformedMemberEntryException e) {
        return new ProblemResponse("malformed_request", e.getMessage());
    }

    public record ProblemResponse(String code, String message) {}
}
