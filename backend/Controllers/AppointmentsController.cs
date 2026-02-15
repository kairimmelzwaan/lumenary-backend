using backend.Dtos;
using backend.Services.Appointments;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Authorize]
[Route("api/appointments")]
public class AppointmentsController(IAppointmentsService appointmentsService) : ControllerBase
{
    [HttpPost]
    public Task<IActionResult> Create(
        [FromBody] AppointmentCreateRequest request,
        CancellationToken cancellationToken)
        => appointmentsService.CreateAsync(request, cancellationToken)
            .ToActionResult(response => CreatedAtAction(nameof(GetById), new { id = response.Id }, response));

    [HttpGet]
    public Task<IActionResult> GetList(
        [FromQuery] Guid? clientId,
        [FromQuery] Guid? therapistUserId,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? status,
        CancellationToken cancellationToken)
        => appointmentsService.GetListAsync(
            new AppointmentListQuery(clientId, therapistUserId, from, to, status),
            cancellationToken).ToActionResult();

    [HttpGet("{id:guid}")]
    public Task<IActionResult> GetById(Guid id, CancellationToken cancellationToken)
        => appointmentsService.GetByIdAsync(id, cancellationToken).ToActionResult();

    [HttpPatch("{id:guid}")]
    public Task<IActionResult> Update(
        Guid id,
        [FromBody] AppointmentUpdateRequest request,
        CancellationToken cancellationToken)
        => appointmentsService.UpdateAsync(id, request, cancellationToken).ToActionResult();

    [HttpGet("/api/me/appointments")]
    public Task<IActionResult> GetMine(
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? status,
        CancellationToken cancellationToken)
        => appointmentsService.GetMineAsync(
            new AppointmentListQuery(null, null, from, to, status),
            cancellationToken).ToActionResult();

    [HttpGet("/api/clients/{clientId:guid}/appointments")]
    public Task<IActionResult> GetForClient(
        Guid clientId,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? status,
        CancellationToken cancellationToken)
        => appointmentsService.GetForClientAsync(
            clientId,
            new AppointmentListQuery(clientId, null, from, to, status),
            cancellationToken).ToActionResult();

    [HttpGet("/api/therapists/{therapistUserId:guid}/appointments")]
    public Task<IActionResult> GetForTherapist(
        Guid therapistUserId,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? status,
        CancellationToken cancellationToken)
        => appointmentsService.GetForTherapistAsync(
            therapistUserId,
            new AppointmentListQuery(null, therapistUserId, from, to, status),
            cancellationToken).ToActionResult();
}
