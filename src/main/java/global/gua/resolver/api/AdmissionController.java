package global.gua.resolver.api;

import jakarta.validation.Valid;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import global.gua.resolver.admission.AdmissionRequest;
import global.gua.resolver.admission.AdmissionService;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.SignedRoster;

/**
 * Authority admin surface for federation membership (§3, §5). All under {@code /authority/**}, which the
 * SecurityConfig requires authentication for. Admit vets + records a new homeserver; status changes
 * suspend/revoke one. Every call appends to the transparency log and returns the freshly re-signed roster.
 */
@RestController
@RequestMapping("/authority")
@ConditionalOnProperty(name = "gua.resolver.mode", havingValue = "AUTHORITY", matchIfMissing = true)
public class AdmissionController {

    private final AdmissionService admission;

    public AdmissionController(AdmissionService admission) {
        this.admission = admission;
    }

    /** Admit a new homeserver into the roster. */
    @PostMapping("/admission")
    public SignedRoster admit(@Valid @RequestBody AdmissionRequest request) {
        return admission.admit(request);
    }

    /** Suspend or revoke an admitted homeserver. */
    @PostMapping("/roster/{id}/status")
    public SignedRoster setStatus(@PathVariable String id, @RequestParam RosterEntry.Status status) {
        return admission.setStatus(id, status);
    }

    @ExceptionHandler(AdmissionService.AdmissionException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ProblemResponse onAdmissionError(AdmissionService.AdmissionException e) {
        return new ProblemResponse("admission_rejected", e.getMessage());
    }

    public record ProblemResponse(String code, String message) {}
}
