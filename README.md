# **Zero Knowledge Proof: Proving Random Bits**

Using `zkSnarks` to prove random bits between Peggy and Victor

> Used `Zokrates` library for implementing zkSnarks.

## **Steps performed** 

* Victor performed the computation of the main `reveal_bit.zok` file and put the output in a `reveal_bit_by_Victor`file. 
* Then performed *setup* to create the *proving key* and *verification_key*.
* Copying this proving key in Peggy's directory.

___

* Peggy now compiled the main `reveal_bit.zok` file and put the output in a `reveal_bit_by_Peggy` file.
* Peggy then computed a `witness`.
* Then created a `proof` using witness , Victor's proving key and the compiled program.
* Now Victor verifies this proof using his `verification key`.  
___

> Zokrates use `Groth16` proving scheme as default.
___

