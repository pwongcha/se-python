"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from aktest_se.types import BaseModel, Nullable, UNSET_SENTINEL
from aktest_se.utils import FieldMetadata, PathParamMetadata, QueryParamMetadata
import pydantic
from pydantic import model_serializer
from typing import Optional
from typing_extensions import Annotated, NotRequired, TypedDict


class GetChangeDeploymentScheduleRequestTypedDict(TypedDict):
    change_id: int
    r"""The change for this enrollment on which to perform the desired operation."""
    enrollment_id: int
    r"""Enrollment on which to perform the desired operation."""
    account_switch_key: NotRequired[str]
    r"""For customers who manage more than one account, this [runs the operation from another account](https://techdocs.akamai.com/developer/docs/manage-many-accounts-with-one-api-client). The Identity and Access Management API provides a [list of available account switch keys](https://techdocs.akamai.com/iam-api/reference/get-client-account-switch-keys)."""


class GetChangeDeploymentScheduleRequest(BaseModel):
    change_id: Annotated[
        int,
        pydantic.Field(alias="changeId"),
        FieldMetadata(path=PathParamMetadata(style="simple", explode=False)),
    ]
    r"""The change for this enrollment on which to perform the desired operation."""

    enrollment_id: Annotated[
        int,
        pydantic.Field(alias="enrollmentId"),
        FieldMetadata(path=PathParamMetadata(style="simple", explode=False)),
    ]
    r"""Enrollment on which to perform the desired operation."""

    account_switch_key: Annotated[
        Optional[str],
        pydantic.Field(alias="accountSwitchKey"),
        FieldMetadata(query=QueryParamMetadata(style="form", explode=True)),
    ] = None
    r"""For customers who manage more than one account, this [runs the operation from another account](https://techdocs.akamai.com/developer/docs/manage-many-accounts-with-one-api-client). The Identity and Access Management API provides a [list of available account switch keys](https://techdocs.akamai.com/iam-api/reference/get-client-account-switch-keys)."""


class GetChangeDeploymentScheduleResponseBodyTypedDict(TypedDict):
    r"""If you want CPS to automatically deploy your certificate, but you don't want the deployment to occur before a certain date and time, you can set a deploy after date. You can only set a deploy after date and time for the renewal of a certificate or for a certificate that's active on the network. The certificate may not deploy at the exact time and date you specify, but it won't deploy before that time and date."""

    not_after: Nullable[str]
    r"""The time when the change is no longer in effect. This value is an ISO 8601 timestamp."""
    not_before: Nullable[str]
    r"""The time when you want the change to take effect. If you don't set this, the change occurs immediately, although most changes take some time to take effect even when they're immediately effective. This value is an ISO 8601 timestamp."""


class GetChangeDeploymentScheduleResponseBody(BaseModel):
    r"""If you want CPS to automatically deploy your certificate, but you don't want the deployment to occur before a certain date and time, you can set a deploy after date. You can only set a deploy after date and time for the renewal of a certificate or for a certificate that's active on the network. The certificate may not deploy at the exact time and date you specify, but it won't deploy before that time and date."""

    not_after: Annotated[Nullable[str], pydantic.Field(alias="notAfter")]
    r"""The time when the change is no longer in effect. This value is an ISO 8601 timestamp."""

    not_before: Annotated[Nullable[str], pydantic.Field(alias="notBefore")]
    r"""The time when you want the change to take effect. If you don't set this, the change occurs immediately, although most changes take some time to take effect even when they're immediately effective. This value is an ISO 8601 timestamp."""

    @model_serializer(mode="wrap")
    def serialize_model(self, handler):
        optional_fields = []
        nullable_fields = ["notAfter", "notBefore"]
        null_default_fields = []

        serialized = handler(self)

        m = {}

        for n, f in self.model_fields.items():
            k = f.alias or n
            val = serialized.get(k)
            serialized.pop(k, None)

            optional_nullable = k in optional_fields and k in nullable_fields
            is_set = (
                self.__pydantic_fields_set__.intersection({n})
                or k in null_default_fields
            )  # pylint: disable=no-member

            if val is not None and val != UNSET_SENTINEL:
                m[k] = val
            elif val != UNSET_SENTINEL and (
                not k in optional_fields or (optional_nullable and is_set)
            ):
                m[k] = val

        return m
