# Provider capacity and model routing

## Purpose

This planned product area is intended to make capacity and model-routing
decisions legible across a dynamic account pool, resource admission, provider
choices, and cache telemetry.

## Planned boundary and interfaces

The planned boundary covers account-pool and Home-Lifecycle inputs, resource
admission with htop-/telemetry inputs, multi-provider capacity including
Gemini/Vertex, model-catalog/routing policy, and cache telemetry. Its
principal documented interfaces are the resolver, account-aware selection, and
versioned configuration.

## Was heute dokumentiert ist

- [Agent pool](agent-pool.md)
- [Account-aware selection](account-aware-selection.md)
- [Home-broker boundary](operations/the-hive-home-broker.md)
- [Recovery](operations/recovery.md)
- [Resource monitor](operations/resource-monitor.md)
- [Control plane](control-plane.md)
- [Resolver](resolver.md)
- [Configuration](configuration.md)

## Geplant

Dynamic capacity across providers, including Gemini/Vertex, model routing, and
cache telemetry are planned capabilities. This page makes no claim about a
provider connection, credentials, cloud billing, runtime, service,
installation, or deployment.

## Roadmap

This area belongs to [Meilenstein 4: Providerkapazität und Modellrouting](../ROADMAP.md#meilenstein-4-providerkapazität-und-modellrouting-geplant).
