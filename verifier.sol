
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x04def3db4bef2a4978f54c3c6e88bb09ff219e5fcc4ef687227998c125544b62), uint256(0x2a3bf44be271d961238edbb5cd86054cb2f9834329db8742b9f859492f200ac1));
        vk.beta = Pairing.G2Point([uint256(0x1bc45a3494a411a75671abbb91456ce2a40420eb55c668ef522833944d88dff0), uint256(0x1ce5210790e01646832cf153428491590bc2534146823966e27973432a676154)], [uint256(0x13b64cd06057b6bd7ec49e51cb548e639b884aebea68e286775df6104a22a4c1), uint256(0x21015b275d1904f538e408a15f1ad68c20471fa16b6540d9fa7ba127543f9af1)]);
        vk.gamma = Pairing.G2Point([uint256(0x1343936fb690392846c9abe2df109813baa2253e20abd38a0e192645fcf5fc4d), uint256(0x08c27d93f4318af544283fd532d113068d636a9e834f1ee70c8c5db456f85264)], [uint256(0x1f59ff501b1390be9e8fdba5703fb9becb8c9519d1a4559ef5a98e40649651f9), uint256(0x0a87e6b820106bb8fcc4969dc60170a18f24fadcc4bac006686c817944f2c440)]);
        vk.delta = Pairing.G2Point([uint256(0x1ef8a1eca9dc6255af63054aeb5edc1466585ac9237371091800c8d73af68543), uint256(0x0762a331040427547d29201ffdb8a809aa87dcb7c723ec88ddfe9d5d69138f16)], [uint256(0x050f08ea278aaaf4d18607bf69961eea63f43848d6800fd3a80a5e99daa89317), uint256(0x00732a64241a860e7e2f70d1396671f4830572ac777b1375a7a21c0ec22447ec)]);
        vk.gamma_abc = new Pairing.G1Point[](11);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0d0cf1d52af0926566f7c8f889f7032a77621cb505f340662f9011e796b89786), uint256(0x18939ca3361f96088b178c56d1b38d5691a46653e97e5c7f2038ad8a8c59c22b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1a1ee9fe77ead66bc4bb5e034e56693a14e71ad9c092a1c2108d00d1bbc40fae), uint256(0x2d8c79ed112c61bb1791a1593daa31e1c29f9503aeb572cfd3dc5be0857538d3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0a42d879bc914d87600cbea8b2e33360303035793ec2f57898a7855190c85f7a), uint256(0x1cb4390d24eef89e86c98307165ffd4929dc841b0577aa2e86e9251b4e7b21b3));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x034308d760d0f48ee27cbaca1c69379955d863a828ea90feafab2ceaad63838d), uint256(0x1d2f47816ecbd9cd6b24cfa19964c3f5a1916cc5867511fdc6268922a8280479));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x22e6d9cf3ffd1814836ce3e439b7260ae69bddf06e7da08b351702f4c932fd4f), uint256(0x21a3b19b1886cc71e5cfb7752e698b3539fc1a4bd8f948f50bdf6de28c0542d1));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x054cc2ae4d2e426b2e53f7a15486f71e778ad846b48211ce19273acab93915b2), uint256(0x177067a7f3b3ff943e1379dcb88d99452e16383c9fe6cd37f1a5eb99778ddfcb));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x221431302a11196305ce474a2cca68d8a44499e8a664982f903365b1480d1d56), uint256(0x1461e39ab130b69d29c3f3687d6dbc7e1fe24b8c992e3a5040d7c16c7fb3d35e));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2a308d16a3378477a434811e11f904d6ae6799a3fcb19cc6752d39ad696f0208), uint256(0x183aabc24322a57f88b949791dc0dda61aaa3ab1c590a14e3aa0c163bb74b0e1));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0e9cd3ff226d928fc52dcc7acd021e5bca2fa4c6963fad7f9f6e83113c21fe51), uint256(0x112a60cf110bc01df73adc28aa94a00a4abbfe9804feadd319b0242f04be7641));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2fee1f5eedff08c9f1023955d56a07e9b21a6c5aa20943315604907b09f9e74d), uint256(0x2f9006873062e86ac5214d7973a25bd3c4a419377c2873e54034d980eb8d2aef));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x03d3245983fa8b7093415ef377108186088c9ca08fd8588e7fdbf22e18c3de34), uint256(0x1e9250432f97ff37b031478c6fdb2c99cf637ffd8117de958975087c3956f7a8));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[10] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](10);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
