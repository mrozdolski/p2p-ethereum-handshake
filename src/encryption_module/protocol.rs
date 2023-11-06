use aes::cipher::{KeyIvInit, StreamCipher};
use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac as h_mac};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use crate::utils_module::utils::{Aes128Ctr64BE, Error, Result};

pub struct EllipticCurveIES {
    pub private_key: SecretKey,
    pub private_ephemeral_key: SecretKey,
    pub public_key: PublicKey,
    pub remote_public_key: PublicKey,
    pub shared_key: H256,
    pub nonce: H256,
    pub auth: Option<Bytes>,
    pub auth_response: Option<Bytes>,
}

impl EllipticCurveIES {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        let private_ephemeral_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let shared_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&remote_public_key, &private_key)[..32],
        );

        Self {
            private_key,
            private_ephemeral_key,
            public_key,
            remote_public_key,
            shared_key,
            nonce: H256::random(),
            auth: None,
            auth_response: None,
        }
    }

    pub fn decrypt_data<'a>(
        &mut self,
        data_in: &'a mut [u8],
        read_bytes: &mut u16,
    ) -> Result<&'a mut [u8]> {
        let payload_size = u16::from_be_bytes([data_in[0], data_in[1]]);
        *read_bytes = payload_size + 2;

        self.auth_response = Some(Bytes::copy_from_slice(
            &data_in[..payload_size as usize + 2],
        ));

        let (_size, rest) = data_in.split_at_mut(2);
        let (pub_data, rest) = rest.split_at_mut(65);
        let remote_emphmeral_pub_key = PublicKey::from_slice(pub_data).unwrap();

        let (iv, rest) = rest.split_at_mut(16); //
        let (encrypted_data, tag) = rest.split_at_mut(payload_size as usize - (65 + 16 + 32));

        let tag = H256::from_slice(&tag[..32]);
        let shared_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&remote_emphmeral_pub_key, &self.private_key)
                [..32],
        );

        let mut key = [0_u8; 32];
        concat_kdf::derive_key_into::<sha2::Sha256>(shared_key.as_bytes(), &[], &mut key).unwrap();

        let encrypted_key = H128::from_slice(&key[..16]);
        let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());

        let iv = H128::from_slice(iv);

        let remote_tag = {
            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_ref()).unwrap();
            hmac.update(iv.as_bytes());
            hmac.update(encrypted_data);
            hmac.update(&payload_size.to_be_bytes());

            H256::from_slice(&hmac.finalize().into_bytes())
        };

        if tag != remote_tag {
            return Err(Error::InvalidTag(remote_tag));
        }

        let mut decryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data);

        Ok(encrypted_data)
    }

    pub fn encrypt_data(&self, data_in: BytesMut, data_out: &mut BytesMut) -> Result<usize> {
        let random_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        let shared_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&self.remote_public_key, &random_secret_key)
                [..32],
        );

        let mut key = [0u8; 32];
        concat_kdf::derive_key_into::<sha2::Sha256>(shared_key.as_bytes(), &[], &mut key).unwrap();
        let iv = H128::random();

        let encrypted_key = H128::from_slice(&key[..16]);
        let mac_key = H256::from(Sha256::digest(&key[16..]).as_ref());

        let mut encryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());

        let total_size: u16 = u16::try_from(65 + 16 + data_in.len() + 32).unwrap();

        let mut encrypted = data_in;
        encryptor.apply_keystream(&mut encrypted);

        let d = {
            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_ref()).unwrap();
            hmac.update(iv.as_bytes());
            hmac.update(&encrypted);
            hmac.update(&total_size.to_be_bytes());

            H256::from_slice(&hmac.finalize().into_bytes())
        };

        data_out.extend_from_slice(&total_size.to_be_bytes());
        data_out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &random_secret_key).serialize_uncompressed(),
        );
        data_out.extend_from_slice(iv.as_bytes());
        data_out.extend_from_slice(&encrypted);
        data_out.extend_from_slice(d.as_bytes());

        Ok(data_out.len())
    }
}
