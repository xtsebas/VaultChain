from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from .models import Block


@require_http_methods(['GET'])
def get_chain(request):
    """
    GET /blockchain/
    Retorna la cadena completa ordenada por índice.
    """
    blocks = list(Block.objects.order_by('index'))
    return JsonResponse({
        'length': len(blocks),
        'chain': [
            {
                'index':         b.index,
                'timestamp':     b.timestamp.isoformat(),
                'sender_id':     str(b.sender_id) if b.sender_id else None,
                'recipient_id':  str(b.recipient_id) if b.recipient_id else None,
                'message_hash':  b.message_hash,
                'previous_hash': b.previous_hash,
                'nonce':         b.nonce,
                'hash':          b.hash,
            }
            for b in blocks
        ],
    })


@require_http_methods(['GET'])
def verify_chain(request):
    """
    GET /blockchain/verify
    Recorre toda la cadena verificando:
      1. El hash almacenado coincide con compute_hash() del bloque.
      2. previous_hash coincide con el hash del bloque anterior.
    Si encuentra una inconsistencia devuelve valid=False e indica el bloque.
    """
    blocks = list(Block.objects.order_by('index'))

    if not blocks:
        return JsonResponse({'valid': False, 'error': 'Blockchain vacío'}, status=500)

    for i, block in enumerate(blocks):
        # Hash interno del bloque debe coincidir
        if block.hash != block.compute_hash():
            return JsonResponse({
                'valid':   False,
                'failed_at_index': block.index,
                'reason':  'hash_mismatch',
                'detail':  f'El hash almacenado del bloque #{block.index} no coincide con su compute_hash().',
            })

        # A partir del segundo bloque, previous_hash debe apuntar al anterior
        if i > 0 and block.previous_hash != blocks[i - 1].hash:
            return JsonResponse({
                'valid':   False,
                'failed_at_index': block.index,
                'reason':  'broken_link',
                'detail':  (
                    f'El bloque #{block.index} apunta a previous_hash={block.previous_hash[:16]}… '
                    f'pero el hash del bloque #{blocks[i-1].index} es {blocks[i-1].hash[:16]}…'
                ),
            })

    return JsonResponse({
        'valid':  True,
        'length': len(blocks),
        'detail': f'Cadena íntegra. {len(blocks)} bloque(s) verificado(s).',
    })


@require_http_methods(['GET'])
def verify_chain_from(request):
    """
    GET /blockchain/verify/from/?from=<index>
    Verifica la integridad de la cadena desde el genesis hasta el bloque indicado.
    """
    from_param = request.GET.get('from')

    if from_param is None:
        return JsonResponse({'error': 'Parámetro "from" requerido'}, status=400)

    try:
        from_index = int(from_param)
    except ValueError:
        return JsonResponse({'error': 'El parámetro "from" debe ser un entero'}, status=400)

    blocks = list(Block.objects.filter(index__lte=from_index).order_by('index'))

    if not blocks:
        return JsonResponse({'valid': False, 'error': 'No se encontraron bloques'}, status=404)

    if blocks[-1].index != from_index:
        return JsonResponse(
            {'error': f'El bloque #{from_index} no existe'},
            status=404,
        )

    for i, block in enumerate(blocks):
        if block.hash != block.compute_hash():
            return JsonResponse({
                'valid':           False,
                'from_index':      from_index,
                'failed_at_index': block.index,
                'reason':          'hash_mismatch',
                'detail':          f'El hash almacenado del bloque #{block.index} no coincide con su compute_hash().',
            })

        if i > 0 and block.previous_hash != blocks[i - 1].hash:
            return JsonResponse({
                'valid':           False,
                'from_index':      from_index,
                'failed_at_index': block.index,
                'reason':          'broken_link',
                'detail':          (
                    f'El bloque #{block.index} apunta a previous_hash={block.previous_hash[:16]}… '
                    f'pero el hash del bloque #{blocks[i-1].index} es {blocks[i-1].hash[:16]}…'
                ),
            })

    return JsonResponse({
        'valid':      True,
        'from_index': from_index,
        'length':     len(blocks),
        'detail':     f'Cadena íntegra desde genesis hasta bloque #{from_index}. {len(blocks)} bloque(s) verificado(s).',
    })
