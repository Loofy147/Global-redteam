from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

class WithdrawRequest(BaseModel):
    amount: int = Field(..., gt=0)
