# Hive bus and resume

## Purpose

This planned product area is intended to preserve coordination topics so that
their archive and resume boundaries can be understood without treating source
artifacts as an operating transport.

## Planned boundary and interfaces

The planned boundary covers durable topic handling, archive, and resume. Its
principal documented interfaces are the architecture, control plane, and
resolver; broker, consumer, and transport behavior are not documented here as
available capabilities.

## Was heute dokumentiert ist

- [Architecture](architecture.md)
- [Control plane](control-plane.md)
- [Resolver](resolver.md)

## Geplant

A durable topic bus with archive and resume boundaries is planned. The
source/test coordination foundation does not establish a running broker,
consumer, transport, service, deployment, or runtime.

## Roadmap

This area belongs to [Meilenstein 5: Topic-Bus, Archiv und Resume](../ROADMAP.md#meilenstein-5-topic-bus-archiv-und-resume-geplant).
