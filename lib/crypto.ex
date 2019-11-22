defmodule Hawk.Crypto do
  alias Hawk.Models.Credentials
  alias Hawk.Models.Artifacts

  def normalize_string(type, %Artifacts{} = artifacts) do
    "hawk.1.#{type}\n" <>
      "#{artifacts.ts}\n" <>
      "#{artifacts.nonce}\n" <>
      "#{:string.uppercase(artifacts.method || "")}\n" <>
      "#{artifacts.resource || ""}\n" <>
      "#{:string.lowercase(artifacts.host || "")}\n" <>
      "#{artifacts.port}\n" <>
      "#{artifacts.hash || ""}\n" <>
      "#{artifacts.ext || ""}\n"
  end

  def generate_random_string(length) do
    :crypto.strong_rand_bytes(length)
    |> Base.encode64()
    |> binary_part(0, length)
  end

  def calculate_mac(type, %Credentials{} = credentials, %Artifacts{} = artifacts) do
    normalized = normalize_string(type, artifacts)

    :crypto.hmac(credentials.algorithm, credentials.key, normalized)
    |> Base.encode64()
  end

  def calculate_payload_hash(payload, algorithm, content_type) do
    :crypto.hash_init(algorithm)
    |> :crypto.hash_update("hawk.1.payload\n")
    |> :crypto.hash_update("#{content_type}\n")
    |> :crypto.hash_update("#{payload || ""}\n")
    |> :crypto.hash_final()
    |> Base.encode64()
  end
end
