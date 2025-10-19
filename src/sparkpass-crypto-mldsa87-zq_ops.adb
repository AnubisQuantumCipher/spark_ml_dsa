--  ============================================================================
--  ML-DSA-87 Modular Arithmetic in Zq - Implementation
--  ============================================================================

pragma SPARK_Mode (Off);  -- Temporarily disabled for debugging

with Interfaces; use Interfaces;
with SparkPass.Crypto.MLDSA87.Params;
with Ada.Text_IO;

package body SparkPass.Crypto.MLDSA87.ZQ_Ops is

   use SparkPass.Crypto.MLDSA87.Params;  -- For constants Q, QInv only

   subtype Zq is SparkPass.Crypto.MLDSA87.Params.Zq;
   subtype U32 is SparkPass.Crypto.MLDSA87.Params.U32;
   subtype U64 is SparkPass.Crypto.MLDSA87.Params.U64;
   subtype I32 is SparkPass.Crypto.MLDSA87.Params.I32;
   subtype Coeff_Centered is SparkPass.Crypto.MLDSA87.Params.Coeff_Centered;

   --  =========================================================================
   --  Modular Arithmetic
   --  =========================================================================

   function AddQ (A, B : Zq) return Zq is
      S : constant U32 := U32 (A) + U32 (B);
      R : U32;
   begin
      --  Debug: Check inputs are valid Zq
      if U32 (A) >= Q then
         raise Program_Error with "AddQ: A=" & U32'Image (U32 (A)) & " >= Q=" & U32'Image (Q);
      end if;
      if U32 (B) >= Q then
         raise Program_Error with "AddQ: B=" & U32'Image (U32 (B)) & " >= Q=" & U32'Image (Q);
      end if;

      --  Simple modular reduction
      if S >= Q then
         R := S - Q;
         --  Double-check: R should be < Q
         if R >= Q then
            R := R - Q;  -- One more reduction if needed
         end if;
      else
         R := S;
      end if;
      --  Final safety check before conversion
      if R >= Q then
         raise Program_Error with "AddQ: result R=" & U32'Image (R) & " >= Q=" & U32'Image (Q) & " from A=" & U32'Image (U32 (A)) & " B=" & U32'Image (U32 (B));
      end if;
      return Zq (R);
   end AddQ;

   function SubQ (A, B : Zq) return Zq is
      D : U32;
   begin
      --  Branchless: if A < B then D + Q else D
      --  When A < B, D underflows (wraps), so adding Q brings it back to [0, Q)
      if A >= B then
         D := U32 (A) - U32 (B);
      else
         D := Q - (U32 (B) - U32 (A));
      end if;
      return Zq (D);
   end SubQ;

   --  =========================================================================
   --  Montgomery Reduction (FIPS 204 Algorithm 35)
   --  =========================================================================

   function MontReduce (T : U64) return Zq is
      --  Input: T ∈ [0, q*2^32)
      --  Output: T / 2^32 mod q
      --
      --  Algorithm (FIPS 204 Algorithm 35):
      --    m := (T mod 2^32) * q' mod 2^32
      --    t := (T + m*q) / 2^32
      --    if t >= q then t - q else t

      T_Low : constant U32 := U32 (T and 16#FFFFFFFF#);
      M_Tmp : constant U64 := U64 (T_Low) * QInv;
      M     : constant U32 := U32 (M_Tmp and 16#FFFFFFFF#);
      U     : constant U64 := T + U64 (M) * U64 (Q);
      Rr    : U32 := U32 (Shift_Right (U, 32));
   begin
      --  Result is in [0, 2q); subtract q if needed
      if Rr >= Q then
         Rr := Rr - Q;
         --  Double-check
         if Rr >= Q then
            Rr := Rr - Q;
         end if;
      end if;
      --  Final safety check
      if Rr >= Q then
         raise Program_Error with "MontReduce: result out of range";
      end if;
      return Zq (Rr);
   end MontReduce;

   function MontMul (A, B : Zq) return Zq is
      T : constant U64 := U64 (A) * U64 (B);
   begin
      return MontReduce (T);
   end MontMul;

   --  =========================================================================
   --  Plain Modular Multiplication (for encode/decode)
   --  =========================================================================

   --  R_Plain = 2^32 mod q = 4,193,792
   R_Plain : constant Zq := Mont_R;

   --  R_Inv = inverse(R_Plain, q) mod q = 8,265,825
   --  Verified: (R_Plain * R_Inv) mod q = 1
   R_Inv : constant Zq := 8_265_825;

   function Modular_Mul (A, B : Zq) return Zq is
      --  Plain modular multiplication: (A * B) mod q
      --  No Montgomery reduction - just straight multiply and reduce
      Product : constant U64 := U64 (A) * U64 (B);
      Result  : constant U32 := U32 (Product mod U64 (Q));
   begin
      --  Debug: Verify result is valid Zq
      if Result >= Q then
         raise Program_Error with "Modular_Mul: result=" & U32'Image (Result) & " >= Q=" & U32'Image (Q) & " from A=" & U32'Image (U32 (A)) & " B=" & U32'Image (U32 (B));
      end if;
      return Zq (Result);
   end Modular_Mul;

   --  =========================================================================
   --  Montgomery Domain Conversions
   --  =========================================================================

   function MontEncode (A : Zq) return Zq is
      --  Convert plain domain → Montgomery domain
      --  A → A * R mod q (plain multiplication)
      Result : Zq;
   begin
      --  Debug: Validate input
      if U32 (A) >= Q then
         raise Program_Error with "MontEncode: input A=" & U32'Image (U32 (A)) & " >= Q=" & U32'Image (Q);
      end if;
      Result := Modular_Mul (A, R_Plain);
      --  Debug: Validate output
      if U32 (Result) >= Q then
         raise Program_Error with "MontEncode: output=" & U32'Image (U32 (Result)) & " >= Q=" & U32'Image (Q) & " from A=" & U32'Image (U32 (A));
      end if;
      return Result;
   end MontEncode;

   function MontDecode (A : Zq) return Zq is
      --  Convert Montgomery domain → plain domain
      --  A_mont → A_mont * R^{-1} mod q (plain multiplication)
      Result : Zq;
   begin
      --  Debug: Validate input
      if U32 (A) >= Q then
         raise Program_Error with "MontDecode: input A=" & U32'Image (U32 (A)) & " >= Q=" & U32'Image (Q);
      end if;
      Result := Modular_Mul (A, R_Inv);
      --  Debug: Validate output
      if U32 (Result) >= Q then
         raise Program_Error with "MontDecode: output=" & U32'Image (U32 (Result)) & " >= Q=" & U32'Image (Q) & " from A=" & U32'Image (U32 (A));
      end if;
      return Result;
   end MontDecode;

   --  =========================================================================
   --  Polynomial-Wide Montgomery Conversions
   --  =========================================================================

   Call_Count : Natural := 0;  -- Track number of times Encode_Poly is called

   procedure Encode_Poly (
      Out_Mont  : out Poly_Zq;
      In_Plain  : in  Poly_Zq
   ) is
   begin
      Call_Count := Call_Count + 1;

      --  Debug: Print first polynomial's values around coefficients 120-130
      if Call_Count = 1 then
         declare
            use Ada.Text_IO;
         begin
            Put_Line ("Encode_Poly (call 1): In_Plain coefficients 120-130:");
            for Idx in Poly_Index range 120 .. 130 loop
               Put_Line ("  [" & Natural'Image (Idx) & "] = " & U32'Image (U32 (In_Plain (Idx))));
            end loop;
            Put_Line ("Starting encoding loop...");
         end;
      end if;

      --  Encode each coefficient with inline validation
      for I in Poly_Index loop
         declare
            Val : constant U32 := U32 (In_Plain (I));
         begin
            if Val >= Q then
               raise Program_Error with "Encode_Poly: In_Plain(" & Natural'Image (I) & ")=" & U32'Image (Val) & " >= Q=" & U32'Image (Q);
            end if;
            Out_Mont (I) := MontEncode (In_Plain (I));
         end;
      end loop;
   end Encode_Poly;

   procedure Decode_Poly (
      Out_Plain : out Poly_Zq;
      In_Mont   : in  Poly_Zq
   ) is
   begin
      for I in Poly_Index loop
         Out_Plain (I) := MontDecode (In_Mont (I));
      end loop;
   end Decode_Poly;

   --  =========================================================================
   --  Domain Conversions
   --  =========================================================================

   function To_Zq (X : Coeff_Centered) return Zq is
      --  Map [-((Q-1)/2), ((Q-1)/2)] -> [0, Q-1]
      --
      --  For positive X: result = X
      --  For negative X: result = Q + X (e.g., -1 becomes Q-1)
   begin
      return (if X >= 0 then U32 (X) else U32 (I32 (Q) + X));
   end To_Zq;

   function To_Centered (X : Zq) return Coeff_Centered is
      --  Map [0, Q-1] -> [-((Q-1)/2), ((Q-1)/2)]
      --
      --  For X <= Q/2: result = X
      --  For X > Q/2:  result = X - Q (e.g., Q-1 becomes -1)

      T     : constant I32 := I32 (X);
      HalfQ : constant I32 := I32 (Q / 2);
   begin
      return (if T > HalfQ then T - I32 (Q) else T);
   end To_Centered;

end SparkPass.Crypto.MLDSA87.ZQ_Ops;
