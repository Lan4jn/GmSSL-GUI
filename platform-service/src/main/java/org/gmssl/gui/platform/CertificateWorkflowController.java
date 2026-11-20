package org.gmssl.gui.platform;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class CertificateWorkflowController {
  private final CertificateWorkflowService workflowService;
  private final Auth auth;

  public CertificateWorkflowController(CertificateWorkflowService workflowService, Auth auth) {
    this.workflowService = workflowService;
    this.auth = auth;
  }

  @PostMapping("/projects/{pid}/certificate-workflows")
  public ResponseEntity<CertificateWorkflowService.CertificateWorkflowResponse> submitWorkflow(
      @PathVariable String pid,
      @RequestBody CertificateWorkflowService.CertificateWorkflowRequest request,
      HttpServletRequest req) {
    auth.project(req, pid, 2);
    var response = workflowService.execute(pid, request, req);
    return ResponseEntity.ok(response);
  }
}
