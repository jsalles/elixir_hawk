defmodule Hawk do
  alias Hawk.Models.Artifacts
  alias Hawk.Models.Credentials

  import Hawk.Crypto

  def header(
        url,
        method,
        %Credentials{} = credentials,
        payload
      ) do
    %{path: pathname, query: search, host: hostname, port: port} = URI.parse(url)

    artifacts = %Artifacts{
      ts: DateTime.to_unix(DateTime.utc_now()),
      nonce: generate_random_string(6),
      method: method,
      resource: "#{pathname}#{search || ""}",
      host: hostname,
      port: port || 443,
      hash: calculate_payload_hash(payload, credentials.algorithm, "application/json")
    }

    mac = calculate_mac("header", credentials, artifacts)

    "Hawk id=\"#{credentials.id}\", ts=\"#{artifacts.ts}\", nonce=\"#{artifacts.nonce}\", hash=\"#{
      artifacts.hash
    }\", mac=\"#{mac}\""
  end
end
