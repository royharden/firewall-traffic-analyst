"""Normalized event identity and value contracts; not a Zeek parser or action inference."""

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal, Self

from pydantic import Field, IPvAnyAddress, field_validator, model_validator

from ..shared.rulesengine.schemas import BoundaryModel, Count, EvidenceRef, Sha256, Token

Port = Annotated[int, Field(ge=0, le=65535)]
IcmpValue = Annotated[int, Field(ge=0, le=255)]


class EventV1(BoundaryModel):
    schema_version: Literal[1] = 1
    input_sha256: Sha256
    raw_line_number: Annotated[int, Field(ge=1)]
    row_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}:[1-9][0-9]*$")]
    uid: Annotated[str, Field(pattern=r"^C[A-Za-z0-9]{8,24}$")] | None = None
    ts_us: Count
    src: IPvAnyAddress
    dst: IPvAnyAddress
    protocol: Literal["tcp", "udp", "icmp"]
    src_port: Port | None = None
    dst_port: Port | None = None
    icmp_type: IcmpValue | None = None
    icmp_code: IcmpValue | None = None
    action: Literal["unknown"] = "unknown"
    conn_state: Annotated[str, Field(pattern=r"^[A-Z0-9]{1,16}$")] | None = None
    orig_bytes: Count | None = None
    resp_bytes: Count | None = None
    total_bytes: Count | None = None
    duration_us: Count | None = None
    direction: Literal["inbound", "outbound", "internal", "external", "unknown"] = "unknown"
    quality_flags: tuple[Token, ...] = ()

    @field_validator("src", "dst", mode="before")
    @classmethod
    def require_ip_text(cls, value: object) -> str | IPv4Address | IPv6Address:
        if not isinstance(value, (str, IPv4Address, IPv6Address)) or "%" in str(value):
            raise ValueError("IP must be explicit address text without a zone identifier")
        return value

    @model_validator(mode="after")
    def check_event_contract(self) -> Self:
        if self.row_id != f"{self.input_sha256}:{self.raw_line_number}":
            raise ValueError("row identity must bind full input digest and physical line")
        if self.protocol == "icmp":
            if self.src_port is not None or self.dst_port is not None:
                raise ValueError("ICMP type/code cannot be represented as TCP/UDP service ports")
            if self.icmp_type is None or self.icmp_code is None:
                raise ValueError("ICMP needs explicit type and code")
        elif self.icmp_type is not None or self.icmp_code is not None:
            raise ValueError("TCP/UDP cannot carry ICMP type/code")
        elif self.src_port is None or self.dst_port is None:
            raise ValueError("TCP/UDP needs both service ports")
        if self.orig_bytes is None or self.resp_bytes is None:
            if self.total_bytes is not None:
                raise ValueError("total bytes unavailable when either direction is unknown")
        elif self.total_bytes is not None and self.total_bytes != self.orig_bytes + self.resp_bytes:
            raise ValueError("declared byte total disagrees with directional counts")
        return self

    @property
    def source_sha256(self) -> str:
        return self.input_sha256

    @property
    def evidence_ref(self) -> EvidenceRef:
        return EvidenceRef(source_sha256=self.input_sha256, row_id=self.row_id)
