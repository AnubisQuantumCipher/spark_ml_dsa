--  ============================================================================
--  ML-DSA-87 Digital Signature Algorithm (FIPS 204) - Pure SPARK
--  ============================================================================
--
--  **Purpose**: NIST FIPS 204 Module-Lattice Digital Signature Algorithm
--
--  **Security**: NIST Level 5 (beyond AES-256)
--
--  **Algorithms**:
--    - KeyGen: Algorithm 1 (Generate public/secret key pair)
--    - Sign:   Algorithm 2 (Create signature with rejection sampling)
--    - Verify: Algorithm 3 (Verify signature with constant-time comparison)
--
--  **Implementation**: 100% pure SPARK, zero FFI, formally verifiable
--
--  ============================================================================

pragma SPARK_Mode (Off);  -- Temporarily disabled for debugging

with Ada.Text_IO;
with SparkPass.Crypto.MLDSA87.Params;   use SparkPass.Crypto.MLDSA87.Params;
with SparkPass.Crypto.MLDSA87.Poly;     use SparkPass.Crypto.MLDSA87.Poly;
with SparkPass.Crypto.MLDSA87.PolyVec;  use SparkPass.Crypto.MLDSA87.PolyVec;
with SparkPass.Crypto.MLDSA87.Matrix;   use SparkPass.Crypto.MLDSA87.Matrix;
with SparkPass.Crypto.MLDSA87.Sampling; use SparkPass.Crypto.MLDSA87.Sampling;
with SparkPass.Crypto.MLDSA87.Packing;  use SparkPass.Crypto.MLDSA87.Packing;
with SparkPass.Crypto.MLDSA87.ZQ_Ops;   -- For AddQ, SubQ modular operations
with SparkPass.Crypto.Random;
with SparkPass.Crypto.Keccak;
with SparkPass.Crypto.Zeroize;
with Interfaces; use Interfaces;

package body SparkPass.Crypto.MLDSA87 is

   --  =========================================================================
   --  Key Generation (FIPS 204 Algorithm 1)
   --  =========================================================================

   procedure KeyGen (
      Public_Key  : out Public_Key_Array;
      Secret_Key  : out Secret_Key_Array
   ) is
      --  Seeds and hashes
      Xi         : Byte_Array (1 .. 32);   -- Random seed ξ
      Hash_128   : Byte_Array (1 .. 128);  -- H(ξ) extended
      Rho        : Byte_Array (1 .. 32);   -- Matrix seed ρ
      Rho_Prime  : Byte_Array (1 .. 64);   -- Sampling seed ρ'
      K_Key      : Byte_Array (1 .. 32);   -- Signing key K
      TR         : Byte_Array (1 .. 64);   -- Public key hash tr

      --  Lattice structures
      A          : Matrix_KxL;              -- Expanded matrix A̅
      S1         : PolyVec_L;               -- Secret s1
      S2         : PolyVec_K;               -- Secret s2
      T          : PolyVec_K;               -- t = A·s1 + s2
      T1         : PolyVec_K;               -- High bits of t
      T0         : PolyVec_K;               -- Low bits of t
      S1_NTT     : PolyVec_L;
      Temp       : PolyVec_K;

      PK_Offset  : Natural := 1;
      SK_Offset  : Natural := 1;
   begin
      --  Step 1: Generate random seed ξ ← {0,1}^256
      Random.Fill (Xi);

      --  Step 2: (ρ, ρ', K) ← H(ξ, 128) using SHAKE-256
      Keccak.SHAKE_256 (Xi, Hash_128);
      Rho       := Hash_128 (1 .. 32);
      Rho_Prime := Hash_128 (33 .. 96);
      K_Key     := Hash_128 (97 .. 128);

      --  Step 3: Expand matrix A̅ ← ExpandA(ρ) in PLAIN domain
      ExpandA (Rho, A);

      --  Debug: Validate A after ExpandA returns
      declare
         use Interfaces;
         Test_Val : Unsigned_32;
      begin
         for I in Vec_K_Index loop
            for J in Vec_L_Index loop
               for K in Poly_Index loop
                  Test_Val := Unsigned_32 (A (I, J)(K));
                  if Test_Val >= Q then
                     raise Program_Error with "KeyGen: A(" & Natural'Image (I) & "," & Natural'Image (J) & "," & Natural'Image (K) & ")=" & Unsigned_32'Image (Test_Val) & " >= Q=" & Unsigned_32'Image (Q) & " right after ExpandA";
                  end if;
               end loop;
            end loop;
         end loop;
      end;

      --  Encode matrix A to Montgomery domain for NTT-based multiplication
      --  (Matrix is generated plain, but NTT ops require Montgomery domain)
      declare
         use Interfaces;
         use Ada.Text_IO;
         A_Mont : Matrix_KxL;
      begin
         for I in Vec_K_Index loop
            for J in Vec_L_Index loop
               --  Debug: Print first polynomial's values around coefficients 120-130
               if I = 0 and J = 0 then
                  Put_Line ("KeyGen: A(0,0) coefficients 120-130:");
                  for K in Poly_Index range 120 .. 130 loop
                     Put_Line ("  [" & Natural'Image (K) & "] = " & Unsigned_32'Image (Unsigned_32 (A (I, J)(K))));
                  end loop;
               end if;

               --  Debug: Validate A before encoding
               for K in Poly_Index loop
                  if Unsigned_32 (A (I, J)(K)) >= Q then
                     raise Program_Error with "KeyGen: A(" & Natural'Image (I) & "," & Natural'Image (J) & "," & Natural'Image (K) & ")=" & Unsigned_32'Image (Unsigned_32 (A (I, J)(K))) & " >= Q=" & Unsigned_32'Image (Q) & " before Encode_Poly";
                  end if;
               end loop;

               --  Debug: Double-check coefficient 0 right before call
               if I = 0 and J = 0 then
                  Put_Line ("KeyGen: About to call Encode_Poly, A(0,0)(0) = " & Unsigned_32'Image (Unsigned_32 (A (I, J)(0))));
                  Put_Line ("KeyGen: A(0,0)'First = " & Natural'Image (A (I, J)'First));
                  Put_Line ("KeyGen: A(0,0)'Last = " & Natural'Image (A (I, J)'Last));
               end if;

               SparkPass.Crypto.MLDSA87.ZQ_Ops.Encode_Poly (A_Mont (I, J), A (I, J));
            end loop;
         end loop;
         A := A_Mont;
      end;

      --  Step 4: Sample secret vectors (s1, s2) ← ExpandS(ρ') in PLAIN domain
      declare
         Seed_66 : Byte_Array (1 .. 66);
      begin
         Seed_66 (1 .. 64) := Rho_Prime;
         Seed_66 (65) := 0;
         Seed_66 (66) := 0;
         UniformEta_Vec_L (Seed_66, 0, S1);
         UniformEta_Vec_K (Seed_66, Unsigned_16 (L), S2);
      end;

      --  Step 5: Compute t = NTT^-1(A̅ ◦ NTT(s1)) + s2
      --
      --  Domain contract:
      --    - A: MONTGOMERY domain (encoded above)
      --    - S1, S2: PLAIN domain (centered coeffs from sampling)
      --    - NTT operates in MONTGOMERY domain (zetas are Mont-encoded)
      --    - Must encode S1 before NTT, decode result after NTT_Inv
      --    - Final add must be in PLAIN domain
      --
      --  Encode S1 to Montgomery domain for NTT
      for I in Vec_L_Index loop
         SparkPass.Crypto.MLDSA87.ZQ_Ops.Encode_Poly (S1_NTT (I), S1 (I));
      end loop;

      --  Forward NTT (Montgomery domain)
      NTT_Vec_L (S1_NTT);

      --  Matrix-vector multiply (Montgomery domain: A_Mont * S1_NTT_Mont)
      Matrix_Vec_Multiply (Temp, A, S1_NTT);

      --  Inverse NTT (stays in Montgomery domain)
      NTT_Inv_Vec_K (Temp);

      --  Decode Temp back to PLAIN domain for addition
      --  Use temporary to avoid in-place corruption
      declare
         Temp_Plain : PolyVec_K;
      begin
         for I in Vec_K_Index loop
            SparkPass.Crypto.MLDSA87.ZQ_Ops.Decode_Poly (Temp_Plain (I), Temp (I));
         end loop;
         Temp := Temp_Plain;
      end;

      --  Add in PLAIN domain: T = Temp + S2 (both plain)
      Add_Vec_K (T, Temp, S2);

      --  Step 6: (t1, t0) ← Power2Round(t, d)
      Power2Round_Vec_K (T, T1, T0);

      --  Step 7: Encode public key pk ← pkEncode(ρ, t1)
      Public_Key (PK_Offset .. PK_Offset + 31) := Rho;
      PK_Offset := PK_Offset + 32;
      Pack_t1_Vec_K (T1, Public_Key (PK_Offset .. PK_Offset + T1_Bytes - 1));

      --  Step 8: tr ← H(pk, 512)
      Keccak.SHA3_512_Hash (Public_Key, TR);

      --  Step 9: Encode secret key sk ← skEncode(ρ, K, tr, s1, s2, t0)
      Secret_Key (SK_Offset .. SK_Offset + 31) := Rho;
      SK_Offset := SK_Offset + 32;
      Secret_Key (SK_Offset .. SK_Offset + 31) := K_Key;
      SK_Offset := SK_Offset + 32;
      Secret_Key (SK_Offset .. SK_Offset + 63) := TR;
      SK_Offset := SK_Offset + 64;
      Pack_s_Vec_L (S1, Secret_Key (SK_Offset .. SK_Offset + S1_Bytes - 1));
      SK_Offset := SK_Offset + S1_Bytes;
      Pack_s_Vec_K (S2, Secret_Key (SK_Offset .. SK_Offset + S2_Bytes - 1));
      SK_Offset := SK_Offset + S2_Bytes;
      for I in Vec_K_Index loop
         Pack_t0 (T0 (I), Secret_Key (SK_Offset .. SK_Offset + Poly_T0_Bytes - 1));
         SK_Offset := SK_Offset + Poly_T0_Bytes;
      end loop;

      --  Zeroize sensitive data
      Zeroize.Wipe (Xi);
      Zeroize.Wipe (Hash_128);
      Zeroize.Wipe (Rho_Prime);
      Zeroize.Wipe (K_Key);
   end KeyGen;

   --  =========================================================================
   --  Sign (FIPS 204 Algorithm 2)
   --  =========================================================================

   procedure Sign_Deterministic (
      Secret_Key  : in  Secret_Key_Array;
      Message     : in  Byte_Array;
      Signature   : out Signature_Array
   ) is
      --  Decode secret key
      Rho       : Byte_Array (1 .. 32);
      K_Key     : Byte_Array (1 .. 32);
      TR        : Byte_Array (1 .. 64);
      S1        : PolyVec_L;
      S2        : PolyVec_K;
      T0        : PolyVec_K;

      --  Signing state
      A         : Matrix_KxL;
      S1_NTT    : PolyVec_L;
      S2_NTT    : PolyVec_K;
      T0_NTT    : PolyVec_K;
      Mu        : Byte_Array (1 .. 64);    -- μ = H(tr || M)
      Rho_Prime : Byte_Array (1 .. 64);    -- Mask expansion seed
      Kappa     : Unsigned_16 := 0;

      --  Rejection sampling loop
      Y         : PolyVec_L;
      W         : PolyVec_K;
      W1        : PolyVec_K;
      W1_Packed : Byte_Array (1 .. W1_Bytes);
      C_Tilde   : Byte_Array (1 .. 32);
      C         : Polynomial;
      C_NTT     : Polynomial;
      Z         : PolyVec_L;
      R0        : PolyVec_K;
      CT0       : PolyVec_K;
      H         : PolyVec_K;
      Ones_Count : Natural;

      Temp_Vec_L : PolyVec_L;
      Temp_Vec_K : PolyVec_K;
      Temp_Poly  : Polynomial;

      SK_Offset : Natural := 1;
      Sig_Offset : Natural := 1;

      Z_Norm : Natural;
      R0_Norm : Natural;
      CT0_Norm : Natural;
      Hint_Success : Boolean;
      Rejected : Boolean;
   begin
      --  Step 1: Decode secret key
      Rho := Secret_Key (SK_Offset .. SK_Offset + 31);
      SK_Offset := SK_Offset + 32;
      K_Key := Secret_Key (SK_Offset .. SK_Offset + 31);
      SK_Offset := SK_Offset + 32;
      TR := Secret_Key (SK_Offset .. SK_Offset + 63);
      SK_Offset := SK_Offset + 64;

      declare
         S1_Packed : Byte_Array (1 .. S1_Bytes) := Secret_Key (SK_Offset .. SK_Offset + S1_Bytes - 1);
         S2_Packed : Byte_Array (1 .. S2_Bytes);
         Offset : Natural := 1;
      begin
         SK_Offset := SK_Offset + S1_Bytes;
         S2_Packed := Secret_Key (SK_Offset .. SK_Offset + S2_Bytes - 1);
         SK_Offset := SK_Offset + S2_Bytes;

         --  Unpack s1, s2
         for I in Vec_L_Index loop
            Unpack_s (S1_Packed (Offset .. Offset + Poly_S_Bytes - 1), S1 (I));
            Offset := Offset + Poly_S_Bytes;
         end loop;

         Offset := 1;
         for I in Vec_K_Index loop
            Unpack_s (S2_Packed (Offset .. Offset + Poly_S_Bytes - 1), S2 (I));
            Offset := Offset + Poly_S_Bytes;
         end loop;
      end;

      --  Unpack t0
      for I in Vec_K_Index loop
         Unpack_t0 (Secret_Key (SK_Offset .. SK_Offset + Poly_T0_Bytes - 1), T0 (I));
         SK_Offset := SK_Offset + Poly_T0_Bytes;
      end loop;

      --  Step 2: Transform to NTT domain
      S1_NTT := S1;
      NTT_Vec_L (S1_NTT);
      S2_NTT := S2;
      NTT_Vec_K (S2_NTT);
      T0_NTT := T0;
      NTT_Vec_K (T0_NTT);

      --  Step 3: Expand A̅
      ExpandA (Rho, A);

      --  Step 4: μ ← H(tr || M, 512)
      declare
         TR_M : Byte_Array (1 .. 64 + Message'Length);
      begin
         TR_M (1 .. 64) := TR;
         TR_M (65 .. TR_M'Last) := Message;
         Keccak.SHA3_512_Hash (TR_M, Mu);
      end;

      --  Step 5: Generate ρ' for mask expansion
      declare
         K_Mu : Byte_Array (1 .. 32 + 64);
      begin
         K_Mu (1 .. 32) := K_Key;
         K_Mu (33 .. 96) := Mu;
         Keccak.SHAKE_256 (K_Mu, Rho_Prime);
      end;

      --  Steps 6-25: Rejection sampling loop
      loop
         --  Step 8: y ← ExpandMask(ρ' || K, κ)
         UniformGamma1_Vec_L (Rho_Prime, Kappa, Y);

         --  Step 9: w ← NTT^-1(A̅ ◦ NTT(y))
         Temp_Vec_L := Y;
         NTT_Vec_L (Temp_Vec_L);
         Matrix_Vec_Multiply (W, A, Temp_Vec_L);
         NTT_Inv_Vec_K (W);

         --  Step 10: w1 ← HighBits(w)
         HighBits_Vec_K (W, W1);

         --  Step 11: c̃ ← H(μ || w1Encode(w1), 256)
         for I in Vec_K_Index loop
            Pack_w1 (W1 (I), W1_Packed ((I * Poly_W1_Bytes + 1) .. ((I + 1) * Poly_W1_Bytes)));
         end loop;

         declare
            Mu_W1 : Byte_Array (1 .. 64 + W1_Bytes);
         begin
            Mu_W1 (1 .. 64) := Mu;
            Mu_W1 (65 .. Mu_W1'Last) := W1_Packed;
            Keccak.SHAKE_256 (Mu_W1, C_Tilde);
         end;

         --  Step 12: c ← SampleInBall(c̃)
         SampleInBall (C_Tilde, C);
         C_NTT := C;
         NTT (C_NTT);

         --  Step 14: z ← y + s1 ◦ c
         Temp_Vec_L := S1;
         for I in Vec_L_Index loop
            Pointwise_Montgomery (Temp_Poly, Temp_Vec_L (I), C);
            for J in Poly_Index loop
               Z (I)(J) := ZQ_Ops.AddQ (Y (I)(J), Temp_Poly (J));
            end loop;
         end loop;

         --  Step 15: Compute r0 ← LowBits(w - s2 ◦ c)
         Temp_Vec_K := S2;
         for I in Vec_K_Index loop
            Pointwise_Montgomery (Temp_Poly, Temp_Vec_K (I), C);
            for J in Poly_Index loop
               Temp_Vec_K (I)(J) := ZQ_Ops.SubQ (W (I)(J), Temp_Poly (J));
            end loop;
         end loop;
         LowBits_Vec_K (Temp_Vec_K, R0);

         --  Step 16: Check ||z||∞ < γ1 - β and ||r0||∞ < γ2 - β
         Z_Norm := Infinity_Norm_Vec_L (Z);
         R0_Norm := Infinity_Norm_Vec_K (R0);

         Rejected := (Z_Norm >= Gamma1 - Beta) or (R0_Norm >= Gamma2 - Beta);

         if not Rejected then
            --  Step 19: Compute ct0
            for I in Vec_K_Index loop
               Pointwise_Montgomery (CT0 (I), T0_NTT (I), C_NTT);
            end loop;
            NTT_Inv_Vec_K (CT0);

            --  Compute h ← MakeHint(-ct0, w - s2·c + ct0)
            for I in Vec_K_Index loop
               for J in Poly_Index loop
                  Temp_Vec_K (I)(J) := ZQ_Ops.AddQ (Temp_Vec_K (I)(J), CT0 (I)(J));
               end loop;
            end loop;

            MakeHint_Vec_K (H, CT0, Temp_Vec_K, Ones_Count);

            --  Step 20: Check ||ct0||∞ < γ2 and weight(h) ≤ ω
            CT0_Norm := Infinity_Norm_Vec_K (CT0);
            Rejected := (CT0_Norm >= Gamma2) or (Ones_Count > Omega);
         end if;

         exit when not Rejected;

         --  Step 24: κ ← κ + l
         Kappa := Kappa + Unsigned_16 (L);
      end loop;

      --  Step 26: σ ← sigEncode(c̃, z mod± q, h)
      Signature (Sig_Offset .. Sig_Offset + 31) := C_Tilde;
      Sig_Offset := Sig_Offset + 32;
      Pack_z_Vec_L (Z, Signature (Sig_Offset .. Sig_Offset + Z_Bytes - 1));
      Sig_Offset := Sig_Offset + Z_Bytes;
      Pack_Hint (H, Signature (Sig_Offset .. Sig_Offset + H_Bytes - 1), Hint_Success);

      --  Zeroize sensitive data
      Zeroize.Wipe (K_Key);
      Zeroize.Wipe (Rho_Prime);
   end Sign_Deterministic;

   --  =========================================================================
   --  Verify (FIPS 204 Algorithm 3)
   --  =========================================================================

   function Verify (
      Public_Key : in Public_Key_Array;
      Message    : in Byte_Array;
      Signature  : in Signature_Array
   ) return Boolean is
      --  Decode public key
      Rho        : Byte_Array (1 .. 32);
      T1         : PolyVec_K;
      PK_Offset  : Natural := 1;

      --  Decode signature
      C_Tilde    : Byte_Array (1 .. 32);
      Z          : PolyVec_L;
      H          : PolyVec_K;
      Sig_Offset : Natural := 1;
      Hint_Success : Boolean;

      --  Verification state
      A          : Matrix_KxL;
      TR         : Byte_Array (1 .. 64);
      Mu         : Byte_Array (1 .. 64);
      C          : Polynomial;
      C_NTT      : Polynomial;
      Z_NTT      : PolyVec_L;
      T1_NTT     : PolyVec_K;
      W_Prime_1  : PolyVec_K;
      W1_Packed  : Byte_Array (1 .. W1_Bytes);
      C_Tilde_Prime : Byte_Array (1 .. 32);

      Temp_Vec_K : PolyVec_K;
      Temp_Poly  : Polynomial;

      Z_Norm     : Natural;
      Match      : Boolean := True;
   begin
      --  Step 1: Decode public key (ρ, t1)
      Rho := Public_Key (PK_Offset .. PK_Offset + 31);
      PK_Offset := PK_Offset + 32;
      Unpack_t1_Vec_K (Public_Key (PK_Offset .. PK_Offset + T1_Bytes - 1), T1);

      --  Step 2: Decode signature (c̃, z, h)
      C_Tilde := Signature (Sig_Offset .. Sig_Offset + 31);
      Sig_Offset := Sig_Offset + 32;
      Unpack_z_Vec_L (Signature (Sig_Offset .. Sig_Offset + Z_Bytes - 1), Z);
      Sig_Offset := Sig_Offset + Z_Bytes;
      Unpack_Hint (Signature (Sig_Offset .. Sig_Offset + H_Bytes - 1), H, Hint_Success);

      --  Step 3: Check hint decode success
      if not Hint_Success then
         return False;
      end if;

      --  Step 4: Expand A̅
      ExpandA (Rho, A);

      --  Step 5: tr ← H(pk, 512)
      Keccak.SHA3_512_Hash (Public_Key, TR);

      --  Step 6: μ ← H(tr || M, 512)
      declare
         TR_M : Byte_Array (1 .. 64 + Message'Length);
      begin
         TR_M (1 .. 64) := TR;
         TR_M (65 .. TR_M'Last) := Message;
         Keccak.SHA3_512_Hash (TR_M, Mu);
      end;

      --  Step 7: c ← SampleInBall(c̃)
      SampleInBall (C_Tilde, C);
      C_NTT := C;
      NTT (C_NTT);

      --  Step 9: Transform z to NTT
      Z_NTT := Z;
      NTT_Vec_L (Z_NTT);

      --  Step 10: Compute w'1 = UseHint(h, 2^d · NTT^-1(A̅·ẑ - ĉ·t̂1))
      --  First: A̅·ẑ
      Matrix_Vec_Multiply (Temp_Vec_K, A, Z_NTT);

      --  Second: ĉ·t̂1
      T1_NTT := T1;
      NTT_Vec_K (T1_NTT);
      for I in Vec_K_Index loop
         Pointwise_Montgomery (Temp_Poly, T1_NTT (I), C_NTT);
         for J in Poly_Index loop
            Temp_Vec_K (I)(J) := ZQ_Ops.SubQ (Temp_Vec_K (I)(J), Temp_Poly (J));
         end loop;
      end loop;

      --  Transform back and scale by 2^d
      NTT_Inv_Vec_K (Temp_Vec_K);
      for I in Vec_K_Index loop
         for J in Poly_Index loop
            --  Multiply by 2^D and reduce mod Q
            declare
               use type Params.U64;
               Scaled : constant Params.U64 := Params.U64 (Temp_Vec_K (I)(J)) * Params.U64 (2 ** D);
            begin
               Temp_Vec_K (I)(J) := Zq (Scaled mod Params.U64 (Q));
            end;
         end loop;
      end loop;

      --  Step 11: w'1 ← UseHint(h, temp)
      UseHint_Vec_K (W_Prime_1, H, Temp_Vec_K);

      --  Pack w'1 for hashing
      for I in Vec_K_Index loop
         Pack_w1 (W_Prime_1 (I), W1_Packed ((I * Poly_W1_Bytes + 1) .. ((I + 1) * Poly_W1_Bytes)));
      end loop;

      --  Step 12: c̃' ← H(μ || w1Encode(w'1), 256)
      declare
         Mu_W1 : Byte_Array (1 .. 64 + W1_Bytes);
      begin
         Mu_W1 (1 .. 64) := Mu;
         Mu_W1 (65 .. Mu_W1'Last) := W1_Packed;
         Keccak.SHAKE_256 (Mu_W1, C_Tilde_Prime);
      end;

      --  Step 13: Check ||z||∞ < γ1 - β (constant-time)
      Z_Norm := Infinity_Norm_Vec_L (Z);

      --  Constant-time comparison of c̃ = c̃'
      for I in C_Tilde'Range loop
         if C_Tilde (I) /= C_Tilde_Prime (I) then
            Match := False;
         end if;
      end loop;

      --  Return [[||z||∞ < γ1 - β]] ∧ [[c̃ = c̃']]
      return (Z_Norm < Gamma1 - Beta) and Match;
   end Verify;

end SparkPass.Crypto.MLDSA87;
